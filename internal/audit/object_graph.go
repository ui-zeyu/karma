package audit

// An object graph is one object's relation graph: what the unit, process or
// file declares, what the kernel observes, what its package owns, what sits
// in its installation tree, and which paths its content mentions. Edges
// carry the source that produced them and a confidence, so a kernel
// observation and a lexical lead do not read alike.

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"karma/internal/startup"
	"karma/internal/trust"
)

const (
	objectMaxDepth   = 3
	objectMaxNodes   = 2000
	objectMaxFiles   = 200
	objectMaxLexical = 40
	objectTextBytes  = 2 << 20
	objectBinBytes   = 8 << 20
)

// ParseGraphSeed reads an object selector: an explicit unit:/pid:/path:/pkg:
// prefix, an absolute path, a bare pid, a unit name, or a package name. A
// bare word names a unit when the services list carries it, a package
// otherwise; the syntax check runs before the collection, so a mistyped
// selector fails in milliseconds rather than after the budget.
func ParseGraphSeed(word string) (GraphSeed, error) {
	word = strings.TrimSpace(word)
	kind, value := "", word
	switch {
	case strings.HasPrefix(word, "unit:"):
		kind, value = "unit", strings.TrimPrefix(word, "unit:")
	case strings.HasPrefix(word, "pid:"):
		kind, value = "pid", strings.TrimPrefix(word, "pid:")
	case strings.HasPrefix(word, "path:"):
		kind, value = "path", strings.TrimPrefix(word, "path:")
	case strings.HasPrefix(word, "pkg:"):
		kind, value = "package", strings.TrimPrefix(word, "pkg:")
	case strings.HasPrefix(word, "/"):
		kind = "path"
	case isDigits(word):
		kind = "pid"
	case hasUnitName(word):
		kind = "unit"
	default:
		kind = "package"
	}
	switch kind {
	case "unit":
		if value == "" {
			return GraphSeed{}, fmt.Errorf("graph: empty unit name")
		}
	case "pid":
		if _, err := strconv.Atoi(value); err != nil {
			return GraphSeed{}, fmt.Errorf("graph: %q is not a pid", value)
		}
	case "path":
		if !filepath.IsAbs(value) {
			return GraphSeed{}, fmt.Errorf("graph: %q is not an absolute path", value)
		}
	case "package":
		if value == "" {
			return GraphSeed{}, fmt.Errorf("graph: empty package name")
		}
	}
	return GraphSeed{Kind: kind, Value: value}, nil
}

// GraphView is one object's evidence graph.
type GraphView struct {
	Root     string      `json:"root"`
	RootKind string      `json:"root_kind"`
	Boundary Boundary    `json:"-"`
	Nodes    []GraphNode `json:"nodes"`
	Edges    []GraphEdge `json:"edges"`
	Findings []Finding   `json:"findings"`
	Coverage []string    `json:"coverage,omitempty"`
}

// GraphNode is one object in the graph. Origin and Reach are the same
// evidence the report uses; Missing marks a path an edge named that the disk
// does not carry.
type GraphNode struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Name       string   `json:"name"`
	Path       string   `json:"path,omitempty"`
	Origin     string   `json:"origin,omitempty"`
	Reach      string   `json:"reach,omitempty"`
	Selected   bool     `json:"selected,omitempty"`
	Discovered bool     `json:"discovered,omitempty"`
	Missing    bool     `json:"missing,omitempty"`
	Context    bool     `json:"context,omitempty"`
	Detail     string   `json:"detail,omitempty"`
	Content    *Content `json:"content,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`

	origin Origin
	reach  Reach
	depth  int
}

// GraphEdge is one relation. Source is kernel, unit, package, tree, shell,
// elf, jar, cmdline or lexical; Confidence is high, medium or low.
type GraphEdge struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Kind       string `json:"kind"`
	Source     string `json:"source"`
	Confidence string `json:"confidence"`
	Note       string `json:"note,omitempty"`
}

type graphBuilder struct {
	ctx         context.Context
	snapshot    *Snapshot
	assessor    *assessor
	graph       *GraphBuilder
	queue       []string
	expanded    map[string]bool
	processes   map[int]Process
	trees       map[string]bool
	reverse     bool // a path seed reads the objects that name it
	findings    []Finding
	coverage    []string
	skippedFD   int
	skippedMap  int
	skippedLib  int
	dynamic     int
	budget      int
	minSeverity Severity
}

// BuildObjectGraph walks one object's relation closure over the snapshot.
// The seed arrives parsed, so a mistyped selector fails before the run
// collects anything; the builder only answers whether the object is visible.
func BuildObjectGraph(ctx context.Context, snapshot *Snapshot, seed GraphSeed, minSeverity Severity) (*GraphView, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("graph: no snapshot")
	}
	b := &graphBuilder{
		ctx: ctx, snapshot: snapshot, assessor: newAssessor(snapshot),
		graph:    &GraphBuilder{nodes: map[string]*GraphNode{}, edgeSeen: map[string]bool{}},
		expanded: map[string]bool{}, processes: map[int]Process{},
		trees: map[string]bool{}, budget: objectMaxNodes, minSeverity: minSeverity,
	}
	for _, process := range snapshot.Processes {
		b.processes[process.PID] = process
	}
	root, err := b.seed(seed)
	if err != nil {
		return nil, err
	}
	b.queue = append(b.queue, root)
	for len(b.queue) > 0 {
		if err := ctx.Err(); err != nil {
			b.coverage = append(b.coverage, "graph stopped: "+err.Error())
			break
		}
		if b.budget == 0 {
			b.coverage = append(b.coverage, "graph stopped at its node budget")
			break
		}
		id := b.queue[0]
		b.queue = b.queue[1:]
		b.expand(id)
	}
	return b.finish(root), nil
}

func (b *graphBuilder) seed(seed GraphSeed) (string, error) {
	switch seed.Kind {
	case "unit":
		node := b.addUnit(seed.Value, 0)
		node.Selected = true
		b.enqueue(node.ID)
		return node.ID, nil
	case "pid":
		pid, err := strconv.Atoi(seed.Value)
		if err != nil {
			return "", fmt.Errorf("graph: %q is not a pid", seed.Value)
		}
		if _, ok := b.processes[pid]; !ok {
			return "", fmt.Errorf("graph: process %d is not visible", pid)
		}
		node := b.addProcess(pid, 0)
		node.Selected = true
		b.enqueue(node.ID)
		return node.ID, nil
	case "path":
		node := b.addFile(filepath.Clean(seed.Value), 0)
		node.Selected = true
		// A path seed reads the units/scripts that name it; a unit itself is
		// expanded forward, so its shared targets do not pull in every unit
		// that also points at them.
		b.reverse = unitForFile(node.Path) == ""
		b.enqueue(node.ID)
		return node.ID, nil
	case "package":
		// A bare word can still be a unit in the services list.
		for _, service := range b.snapshot.Services {
			if service.Unit == seed.Value {
				node := b.addUnit(seed.Value, 0)
				node.Selected = true
				b.enqueue(node.ID)
				return node.ID, nil
			}
		}
		node := b.addPackage(seed.Value, 0)
		node.Selected = true
		b.enqueue(node.ID)
		return node.ID, nil
	}
	return "", fmt.Errorf("graph: unknown selector kind %q", seed.Kind)
}

func isDigits(word string) bool {
	if word == "" {
		return false
	}
	for _, c := range word {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func hasUnitName(name string) bool {
	switch {
	case strings.HasSuffix(name, ".service"), strings.HasSuffix(name, ".socket"),
		strings.HasSuffix(name, ".timer"), strings.HasSuffix(name, ".path"),
		strings.HasSuffix(name, ".target"), strings.HasSuffix(name, ".mount"):
		return true
	}
	return false
}

// rootNodeKind reads the root node's kind; a graph without its root falls
// back to the selector's own word.
func rootNodeKind(graph *GraphBuilder, root string) string {
	if node := graph.node(root); node != nil {
		return node.Kind
	}
	return ""
}

func (b *graphBuilder) finish(root string) *GraphView {
	view := b.graph.GraphView(rootNodeKind(b.graph, root), b.snapshot)
	view.Findings = b.localFindings()
	if b.skippedFD > 0 {
		b.coverage = append(b.coverage, fmt.Sprintf("%d open file(s) skipped as package-owned base context", b.skippedFD))
	}
	if b.skippedMap > 0 {
		b.coverage = append(b.coverage, fmt.Sprintf("%d mapped file(s) skipped as package-owned base context", b.skippedMap))
	}
	if b.skippedLib > 0 {
		b.coverage = append(b.coverage, fmt.Sprintf("%d linked library(ies) are package-owned base files", b.skippedLib))
	}
	if b.dynamic > 0 {
		b.coverage = append(b.coverage, fmt.Sprintf("%d reference(s) were dynamic and could not be resolved statically", b.dynamic))
	}
	view.Coverage = uniqueStrings(b.coverage)
	return view
}

func (b *graphBuilder) localFindings() []Finding {
	report := Judge(b.snapshot, Filter{MinSeverity: b.minSeverity})
	paths := map[string]bool{}
	b.graph.each(func(node *GraphNode) {
		if node.Path != "" {
			paths[node.Path] = true
		}
	})
	activationTargets := map[string]bool{}
	for _, edge := range b.snapshot.Activations {
		if !edge.Dynamic {
			activationTargets[edge.Target] = true
		}
	}
	var out []Finding
	covered := map[string]bool{}
	for _, finding := range report.Findings {
		if finding.Severity < b.minSeverity {
			continue
		}
		if paths[finding.Path] {
			out = append(out, finding)
			covered[finding.Path] = true
		}
	}
	// A selected or discovered runtime executable with no package is dormant
	// code the activation and process checks never see. It is the scoped
	// counterpart of the static inventory's unowned-file.
	for _, id := range b.graph.order {
		node := b.graph.nodes[id]
		if node.Kind != "file" || node.Path == "" || node.Missing || covered[node.Path] || activationTargets[node.Path] {
			continue
		}
		facts := b.snapshot.Facts(node.Path)
		if !facts.PackageKnown || facts.Package != "" || !facts.Executable {
			continue
		}
		if node.origin != Runtime && node.origin != Modified {
			continue
		}
		severity := Medium
		reach := UserAsset
		if facts.RootOwned {
			severity = High
			reach = RootAsset
		}
		if severity < b.minSeverity {
			continue
		}
		evidence := append([]string{
			"no package's file list records this path",
			"the file was selected or discovered by the graph",
		}, node.Evidence...)
		out = append(out, Finding{
			Class: "unowned-file", Domain: DomainFiles, Severity: severity, Origin: node.origin, Reach: reach,
			Title:    "runtime executable no package owns",
			Path:     node.Path,
			Detail:   "it is neither an activation target nor a running process; the graph found it",
			Evidence: evidence,
		})
		covered[node.Path] = true
	}
	for _, finding := range b.findings {
		if finding.Severity >= b.minSeverity {
			out = append(out, finding)
		}
	}
	sortFindings(out)
	return out
}

// addNode registers one node and keeps insertion order for the tree.
func (b *graphBuilder) addNode(node *GraphNode) *GraphNode {
	b.graph.add(node)
	return b.graph.node(node.ID)
}

func (b *graphBuilder) addEdge(from, to, kind, source, confidence, note string) {
	b.graph.link(from, to, kind, source, confidence, note)
}

func (b *graphBuilder) enqueue(id string) {
	node := b.graph.node(id)
	if node == nil || node.depth > objectMaxDepth || b.expanded[id] {
		return
	}
	b.queue = append(b.queue, id)
}

func (b *graphBuilder) expand(id string) {
	if b.expanded[id] {
		return
	}
	if b.budget == 0 {
		return
	}
	b.budget--
	b.expanded[id] = true
	node := b.graph.node(id)
	switch node.Kind {
	case "file":
		b.expandFile(node)
	case "process":
		b.expandProcess(node)
	case "unit":
		b.expandUnit(node)
	case "package":
		b.expandPackage(node)
	}
}

func (b *graphBuilder) addFile(path string, depth int) *GraphNode {
	if path == "" || !filepath.IsAbs(path) {
		return &GraphNode{ID: "file:" + path, Kind: "file", Name: path}
	}
	id := "file:" + path
	if node := b.graph.node(id); node != nil {
		return node
	}
	b.snapshot.ensureFacts([]string{path})
	facts := b.snapshot.Facts(path)
	story := b.assessor.read(facts, false)
	node := &GraphNode{
		ID: id, Kind: "file", Name: filepath.Base(path), Path: path,
		Origin: story.origin.String(), origin: story.origin,
		Detail: story.why, Evidence: story.evidence, depth: depth,
		Discovered: depth > 0,
	}
	if facts.Kind == trust.Missing {
		node.Missing = true
		if node.Detail == "" || node.Detail == "not a file or directory" {
			node.Detail = "missing"
		}
	}
	if content, ok := b.snapshot.Verify[facts.Real]; ok {
		copied := content
		node.Content = &copied
	}
	if facts.PackageKnown && facts.Package != "" {
		pkg := b.addPackage(facts.Package, depth+1)
		b.addEdge(id, pkg.ID, "owned-by", "package", "high", "")
	} else if facts.PackageKnown && facts.Package == "" {
		if node.Detail == "" {
			node.Detail = "no package owns it"
		}
		if !strings.Contains(strings.Join(node.Evidence, "\n"), "nearest owned ancestor") {
			if pkg, dir, shared, ok := b.nearestOwner(path); ok {
				if shared {
					node.Evidence = append(node.Evidence, fmt.Sprintf(
						"no package owns it; the nearest owned ancestor %s is shared by several packages", dir))
				} else {
					node.Evidence = append(node.Evidence, fmt.Sprintf(
						"no package owns it; the nearest owned ancestor %s belongs to %s", dir, pkg))
				}
			}
		}
	}
	if facts.Setuid || facts.Caps {
		node.reach = RootAsset
		node.Reach = RootAsset.String()
	}
	return b.addNode(node)
}

// nearestOwner names the closest ancestor a package owns. The graph reads
// ancestors the collection did not judge, so the orphan still carries the tree
// it sits in as evidence.
func (b *graphBuilder) nearestOwner(path string) (pkg, dir string, shared, ok bool) {
	var dirs []string
	for dir = filepath.Dir(path); dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		dirs = append(dirs, dir)
	}
	if len(dirs) == 0 {
		return "", "", false, false
	}
	b.snapshot.ensureFacts(dirs)
	for _, dir = range dirs {
		facts := b.snapshot.Facts(dir)
		if facts.PackageKnown && facts.Package != "" {
			return facts.Package, dir, facts.PackageShared, true
		}
	}
	return "", "", false, false
}

func (b *graphBuilder) addProcess(pid, depth int) *GraphNode {
	id := "process:" + strconv.Itoa(pid)
	if node := b.graph.node(id); node != nil {
		return node
	}
	process, ok := b.processes[pid]
	if !ok {
		return b.addNode(&GraphNode{
			ID: id, Kind: "process", Name: strconv.Itoa(pid), depth: depth,
			Detail: "process not visible", Missing: true, Discovered: depth > 0,
		})
	}
	imageStory := b.assessor.read(process.ExeFacts, false)
	origin := imageStory.origin
	evidence := append([]string(nil), imageStory.evidence...)
	if process.Script != "" {
		scriptStory := b.assessor.read(process.ScriptFacts, false)
		origin = weaker(origin, scriptStory.origin)
		evidence = append(evidence, scriptStory.evidence...)
	}
	reach := processReach(process)
	context := processContext(process)
	if process.Cwd != "" && process.Cwd != "/" {
		context = append(context, "cwd "+process.Cwd)
	}
	node := &GraphNode{
		ID: id, Kind: "process", Name: process.Comm, Path: process.Exe,
		Origin: origin.String(), origin: origin, Reach: reach.String(), reach: reach,
		Detail:   fmt.Sprintf("pid %d uid %d %s", process.PID, process.UID, process.Cmdline),
		Evidence: append(append([]string(nil), evidence...), context...),
		depth:    depth, Discovered: depth > 0,
	}
	return b.addNode(node)
}

func (b *graphBuilder) addUnit(name string, depth int) *GraphNode {
	id := "unit:" + name
	if node := b.graph.node(id); node != nil {
		return node
	}
	node := &GraphNode{ID: id, Kind: "unit", Name: name, depth: depth, Discovered: depth > 0}
	if service, ok := b.service(name); ok {
		node.Detail = service.Load + " " + service.Active + " " + service.Sub
		if service.Description != "" {
			node.Detail += " — " + service.Description
		}
	} else {
		node.Detail = "unit not reported by systemd"
	}
	return b.addNode(node)
}

func (b *graphBuilder) addPackage(name string, depth int) *GraphNode {
	id := "package:" + name
	if node := b.graph.node(id); node != nil {
		return node
	}
	node := &GraphNode{ID: id, Kind: "package", Name: name, depth: depth, Discovered: depth > 0}
	if stamp, ok := b.snapshot.PackageTimes[name]; ok {
		node.Detail = "last transaction " + stamp.Format(stampLayout)
	}
	return b.addNode(node)
}

func (b *graphBuilder) addDir(path string, depth int) *GraphNode {
	if path == "" {
		return &GraphNode{ID: "dir:" + path, Kind: "dir", Name: path}
	}
	id := "dir:" + path
	if node := b.graph.node(id); node != nil {
		return node
	}
	b.snapshot.ensureFacts([]string{path})
	facts := b.snapshot.Facts(path)
	story := b.assessor.read(facts, false)
	return b.addNode(&GraphNode{
		ID: id, Kind: "dir", Name: filepath.Base(path), Path: path,
		Origin: story.origin.String(), origin: story.origin,
		Detail: story.why, Evidence: story.evidence, Context: true,
		depth: depth, Discovered: depth > 0,
	})
}

func (b *graphBuilder) addPeer(peer string, depth int) *GraphNode {
	id := "peer:" + peer
	if node := b.graph.node(id); node != nil {
		return node
	}
	return b.addNode(&GraphNode{
		ID: id, Kind: "peer", Name: peer, Detail: "established peer",
		Context: true, depth: depth, Discovered: depth > 0,
	})
}

func (b *graphBuilder) addSocket(socket Socket, depth int) *GraphNode {
	id := "socket:" + socket.Proto + ":" + socket.Local + ":" + strconv.Itoa(socket.PID)
	if node := b.graph.node(id); node != nil {
		return node
	}
	return b.addNode(&GraphNode{
		ID: id, Kind: "socket", Name: socket.Local,
		Detail: socket.Proto + " " + socket.State + " pid " + strconv.Itoa(socket.PID),
		depth:  depth, Discovered: depth > 0,
	})
}

func (b *graphBuilder) service(name string) (Service, bool) {
	for _, service := range b.snapshot.Services {
		if service.Unit == name || templateUnit(service.Unit) == name {
			return service, true
		}
	}
	return Service{}, false
}

func (b *graphBuilder) expandFile(node *GraphNode) {
	path := node.Path
	if path == "" || node.Missing {
		return
	}
	facts := b.snapshot.Facts(path)
	if facts.Kind == trust.Missing {
		return
	}
	if unit := unitForFile(path); unit != "" {
		// A unit file's relations are the unit's, not the file's: expanding
		// them here would draw every ExecStart edge twice.
		unitNode := b.addUnit(unit, node.depth+1)
		b.addEdge(node.ID, unitNode.ID, "configured-by", "unit", "high", "")
		b.enqueue(unitNode.ID)
		return
	}
	// Activation edges that name this file pull in the other end.
	for _, edge := range b.snapshot.Activations {
		if edge.Dynamic {
			continue
		}
		triggerHit := edge.Trigger == path ||
			(facts.Real != "" && edge.TriggerFacts.Real != "" && edge.TriggerFacts.Real == facts.Real)
		targetHit := edge.Target == path ||
			(facts.Real != "" && edge.TargetFacts.Real != "" && edge.TargetFacts.Real == facts.Real)
		if !triggerHit && !targetHit {
			continue
		}
		if triggerHit && edge.Target != "" {
			target := b.addFile(edge.Target, node.depth+1)
			b.addEdge(node.ID, target.ID, "activates", "unit", "high", string(edge.Mechanism))
			b.enqueue(target.ID)
		}
		if targetHit && edge.Trigger != "" {
			if !b.reverse {
				continue
			}
			if unit := unitForFile(edge.Trigger); unit != "" && b.graph.node("unit:"+unit) != nil {
				// The unit's own expansion already draws this relation.
				continue
			}
			trigger := b.addFile(edge.Trigger, node.depth+1)
			b.addEdge(trigger.ID, node.ID, "activates", "unit", "high", string(edge.Mechanism))
			b.enqueue(trigger.ID)
		}
	}
	if interpreter, ok := shebang(path); ok {
		interp := b.addFile(interpreter, node.depth+1)
		b.addEdge(node.ID, interp.ID, "interpreter", "shebang", "high", "")
	}
	if isShellScript(path, facts) {
		b.shellRefs(node)
	}
	if data, ok := readFileCapped(path, objectTextBytes); ok && isText(data) {
		b.lexicalRefs(node, data, "lexical")
	} else if facts.Executable {
		if data, ok := readFileCapped(path, objectBinBytes); ok {
			b.lexicalRefs(node, data, "strings")
		}
	}
	if facts.Executable && isELF(path) {
		b.elfRefs(node)
	}
	if strings.HasSuffix(strings.ToLower(path), ".jar") {
		b.jarRefs(node)
	}
	if facts.PackageKnown && facts.Package == "" && (node.Selected || facts.Executable) {
		b.containment(node)
	}
}

func (b *graphBuilder) shellRefs(node *GraphNode) {
	data, ok := readFileCapped(node.Path, 256<<10)
	if !ok {
		return
	}
	for _, ref := range startup.References(node.Path, string(data)) {
		if ref.Dynamic || ref.Target == "" {
			b.dynamic++
			continue
		}
		if !filepath.IsAbs(ref.Target) {
			continue
		}
		if ref.Kind == startup.Env || ref.Kind == startup.Preload {
			// A variable may hold a route (VENDOR_RUNTIME_ATTACH_ROUTE) or an
			// install prefix; only an existing file is a reference.
			if info, err := os.Stat(ref.Target); err != nil || !info.Mode().IsRegular() {
				continue
			}
		}
		target := b.addFile(filepath.Clean(ref.Target), node.depth+1)
		b.addEdge(node.ID, target.ID, "references", "shell", "high", string(ref.Mechanism))
		b.enqueue(target.ID)
	}
}

func (b *graphBuilder) lexicalRefs(node *GraphNode, data []byte, source string) {
	if strings.HasSuffix(node.Path, ".log") || strings.Contains(node.Path, "/logs/") {
		return
	}
	paths := extractPaths(data)
	shown := 0
	for _, path := range paths {
		if shown >= objectMaxLexical {
			b.coverage = append(b.coverage, "lexical scan of "+node.Path+" stopped at its path budget")
			break
		}
		if path == node.Path {
			continue
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		target := b.addFile(path, node.depth+1)
		b.addEdge(node.ID, target.ID, "mentions", source, "low", "path string in content")
		shown++
	}
}

var pathTokenRE = regexp.MustCompile(`(?:^|[\s"'=:(,;])/(?:[A-Za-z0-9._+\-@%]+/)*[A-Za-z0-9._+\-@%]+`)

func extractPaths(data []byte) []string {
	var out []string
	seen := map[string]bool{}
	for _, match := range pathTokenRE.FindAll(data, -1) {
		text := string(match)
		index := strings.IndexByte(text, '/')
		if index < 0 {
			continue
		}
		path := strings.TrimRight(text[index:], ".,:;)]}")
		if len(path) < 2 || len(path) > 200 || strings.Contains(path, "..") {
			continue
		}
		if strings.HasPrefix(path, "/proc/") || strings.HasPrefix(path, "/sys/") ||
			strings.HasPrefix(path, "/dev/") || strings.HasPrefix(path, "/run/") {
			continue
		}
		path = filepath.Clean(path)
		if seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	return out
}

func (b *graphBuilder) elfRefs(node *GraphNode) {
	file, err := elf.Open(node.Path)
	if err != nil {
		return
	}
	defer file.Close()
	libs, err := file.ImportedLibraries()
	if err != nil {
		return
	}
	var dirs []string
	for _, key := range []elf.DynTag{elf.DT_RUNPATH, elf.DT_RPATH} {
		values, _ := file.DynString(key)
		for _, value := range values {
			for _, dir := range strings.Split(value, ":") {
				dir = strings.ReplaceAll(dir, "$ORIGIN", filepath.Dir(node.Path))
				if filepath.IsAbs(dir) {
					dirs = append(dirs, dir)
				}
			}
		}
	}
	dirs = append(dirs, "/lib", "/usr/lib", "/lib64", "/usr/lib64")
	for _, lib := range libs {
		found := ""
		for _, dir := range dirs {
			candidate := filepath.Join(dir, lib)
			if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
				found = candidate
				break
			}
		}
		if found == "" {
			continue
		}
		b.snapshot.ensureFacts([]string{found})
		facts := b.snapshot.Facts(found)
		if facts.PackageKnown && facts.Package != "" && !isAppPath(found) {
			b.skippedLib++
			continue
		}
		libNode := b.addFile(found, node.depth+1)
		b.addEdge(node.ID, libNode.ID, "linked", "elf", "high", lib)
	}
}

func (b *graphBuilder) jarRefs(node *GraphNode) {
	reader, err := zip.OpenReader(node.Path)
	if err != nil {
		return
	}
	defer reader.Close()
	for _, entry := range reader.File {
		if entry.Name != "META-INF/MANIFEST.MF" {
			continue
		}
		file, err := entry.Open()
		if err != nil {
			return
		}
		data, _ := io.ReadAll(io.LimitReader(file, 1<<20))
		file.Close()
		classpath := manifestClassPath(string(data))
		for _, item := range classpath {
			if strings.Contains(item, "://") {
				continue
			}
			path := item
			if !filepath.IsAbs(path) {
				path = filepath.Join(filepath.Dir(node.Path), path)
			}
			path = filepath.Clean(path)
			if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
				continue
			}
			target := b.addFile(path, node.depth+1)
			b.addEdge(node.ID, target.ID, "classpath", "jar", "high", "MANIFEST.MF")
		}
		return
	}
}

// manifestClassPath reads the Class-Path header, including its continuation
// lines (a leading space).
func manifestClassPath(body string) []string {
	var joined string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, " ") {
			joined += " " + strings.TrimSpace(line)
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "class-path:") {
			joined += " " + strings.TrimSpace(line[len("class-path:"):])
		}
	}
	return strings.Fields(joined)
}

func (b *graphBuilder) containment(node *GraphNode) {
	root := appRoot(node.Path)
	if root == "" || root == node.Path || b.trees[root] {
		return
	}
	b.trees[root] = true
	b.snapshot.ensureFacts([]string{root})
	story := b.assessor.read(b.snapshot.Facts(root), false)
	dir := b.addNode(&GraphNode{
		ID: "dir:" + root, Kind: "dir", Name: filepath.Base(root), Path: root,
		Origin: story.origin.String(), origin: story.origin, Context: true,
		Detail: "application tree · " + story.why,
		depth:  node.depth + 1, Discovered: true,
	})
	b.addEdge(node.ID, dir.ID, "in-tree", "tree", "medium", "")
	count := 0
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || path == root || path == node.Path {
			return nil
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "__pycache__", "logs", "data":
				return filepath.SkipDir
			}
			if strings.Count(strings.TrimPrefix(path, root), string(filepath.Separator)) > 3 {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() || strings.HasSuffix(path, ".log") {
			return nil
		}
		if !isConfigPath(path) && !strings.HasSuffix(strings.ToLower(path), ".jar") {
			info, err := entry.Info()
			if err != nil || info.Mode().Perm()&0o111 == 0 {
				return nil
			}
		}
		if count >= objectMaxFiles {
			b.coverage = append(b.coverage, "application tree "+root+" stopped at its file budget")
			return filepath.SkipAll
		}
		count++
		child := b.addFile(path, dir.depth+1)
		b.addEdge(dir.ID, child.ID, "contains", "tree", "medium", "")
		return nil
	})
}

func (b *graphBuilder) expandProcess(node *GraphNode) {
	pid, _ := strconv.Atoi(strings.TrimPrefix(node.ID, "process:"))
	process, ok := b.processes[pid]
	if !ok {
		return
	}
	if process.Exe != "" {
		image := b.addFile(process.Exe, node.depth+1)
		b.addEdge(node.ID, image.ID, "executes", "kernel", "high", "image")
		b.enqueue(image.ID)
	}
	if process.Script != "" {
		script := b.addFile(process.Script, node.depth+1)
		b.addEdge(node.ID, script.ID, "executes", "kernel", "high", "script")
		b.enqueue(script.ID)
	}
	if process.Unit != "" {
		unit := b.addUnit(process.Unit, node.depth+1)
		b.addEdge(node.ID, unit.ID, "member-of", "cgroup", "high", process.Cgroup)
		b.enqueue(unit.ID)
	}
	for _, path := range cmdlinePaths(process.Cmdline) {
		target := b.addFile(path, node.depth+1)
		b.addEdge(node.ID, target.ID, "references", "cmdline", "high", "")
		b.enqueue(target.ID)
	}
	for _, path := range openFiles(pid) {
		if !interestingContext(path, process) {
			b.skippedFD++
			continue
		}
		target := b.addFile(path, node.depth+1)
		b.addEdge(node.ID, target.ID, "open", "kernel", "high", "")
		b.enqueue(target.ID)
	}
	for _, path := range mappedFiles(pid) {
		if !interestingContext(path, process) {
			b.skippedMap++
			continue
		}
		target := b.addFile(path, node.depth+1)
		b.addEdge(node.ID, target.ID, "maps", "kernel", "high", "")
	}
	for _, socket := range b.snapshot.Sockets {
		if socket.PID != pid {
			continue
		}
		socketNode := b.addSocket(socket, node.depth+1)
		b.addEdge(node.ID, socketNode.ID, "listens", "kernel", "high", "")
	}
	for _, connection := range b.snapshot.Connections {
		if connection.PID != pid && !containsPID(connection.PIDs, pid) {
			continue
		}
		socketNode := b.addSocket(Socket{
			Proto: connection.Proto, State: "ESTABLISHED", Local: connection.Local,
			Peer: connection.Peer, PID: connection.PID, Comm: connection.Comm,
		}, node.depth+1)
		b.addEdge(node.ID, socketNode.ID, "connects", "kernel", "high", connection.Peer)
		peer := b.addPeer(connection.Peer, node.depth+2)
		b.addEdge(socketNode.ID, peer.ID, "peer", "kernel", "high", "")
	}
	for _, target := range process.LoaderTargets {
		if target.Path == "" || !filepath.IsAbs(target.Path) {
			continue
		}
		library := b.addFile(target.Path, node.depth+1)
		b.addEdge(node.ID, library.ID, "preloads", "environ", "high", target.Variable)
		b.enqueue(library.ID)
	}
	if process.LibraryPath != "" {
		for _, dir := range strings.Split(process.LibraryPath, ":") {
			if dir == "" || dir == "." || !filepath.IsAbs(dir) {
				continue
			}
			libraryDir := b.addDir(dir, node.depth+1)
			b.addEdge(node.ID, libraryDir.ID, "searches", "environ", "medium", "LD_LIBRARY_PATH")
		}
	}
	if parent, ok := b.processes[process.PPID]; ok && parent.PID != process.PID {
		parentNode := b.addProcess(parent.PID, objectMaxDepth+1)
		b.addEdge(node.ID, parentNode.ID, "parent", "kernel", "high", "")
	}
}

func (b *graphBuilder) expandUnit(node *GraphNode) {
	name := node.Name
	found := 0
	for _, edge := range b.snapshot.Activations {
		if edge.Surface != startup.SurfaceSystemd {
			continue
		}
		unit := activationUnit(edge.Trigger)
		if unit != name && templateUnit(unit) != name {
			continue
		}
		found++
		trigger := b.addFile(edge.Trigger, node.depth+1)
		b.addEdge(node.ID, trigger.ID, "configured-by", "unit", "high", "")
		if node.origin == Unknown {
			node.origin = trigger.origin
			node.Origin = trigger.Origin
			if node.Detail == "" {
				node.Detail = trigger.Detail
			} else if trigger.Detail != "" {
				node.Detail += " · " + trigger.Detail
			}
		}
		if edge.Target == "" || edge.Dynamic {
			if edge.Dynamic {
				b.dynamic++
			}
			continue
		}
		target := b.addFile(edge.Target, node.depth+1)
		if edge.Context {
			target.Context = true
		}
		kind := "activates"
		if edge.Mechanism != "" {
			kind = strings.ToLower(string(edge.Mechanism))
		}
		source := "unit"
		if edge.Context {
			source = "unit-decl"
		}
		b.addEdge(node.ID, target.ID, kind, source, "high", string(edge.Mechanism))
		if target.Missing && !edge.Context {
			b.findings = append(b.findings, Finding{
				Class: "unit-target-missing", Domain: DomainPersistence, Severity: Medium, Origin: Unknown, Reach: RootAsset,
				Title:  "unit names a file the disk does not carry",
				Path:   target.Path,
				Detail: fmt.Sprintf("unit %s: %s", name, edge.Mechanism),
				Evidence: []string{
					"declared by " + edge.Trigger,
					"path " + target.Path + " is missing",
				},
			})
		}
		if !edge.Context {
			b.enqueue(target.ID)
		}
	}
	for _, process := range b.snapshot.Processes {
		if process.Unit != name && templateUnit(process.Unit) != name {
			continue
		}
		found++
		processNode := b.addProcess(process.PID, node.depth+1)
		b.addEdge(node.ID, processNode.ID, "runs", "cgroup", "high", process.Cgroup)
		b.enqueue(processNode.ID)
	}
	if found == 0 {
		if path := findUnitFile(name); path != "" {
			file := b.addFile(path, node.depth+1)
			b.addEdge(node.ID, file.ID, "configured-by", "unit", "high", "")
			if node.origin == Unknown {
				node.origin = file.origin
				node.Origin = file.Origin
				node.Detail = file.Detail
			}
			b.enqueue(file.ID)
		} else {
			b.coverage = append(b.coverage, "unit "+name+" has no readable unit file or activation edge")
		}
	}
	// Drop-ins exist even when the unit has no ExecStart edge of its own.
	for _, dir := range unitDirs {
		dropDir := filepath.Join(dir, name+".d")
		entries, err := os.ReadDir(dropDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".conf") {
				continue
			}
			path := filepath.Join(dropDir, entry.Name())
			file := b.addFile(path, node.depth+1)
			b.addEdge(node.ID, file.ID, "drop-in", "unit", "high", "")
		}
	}
}

func (b *graphBuilder) expandPackage(node *GraphNode) {
	shown := 0
	for path, facts := range b.snapshot.Objects {
		if !facts.PackageKnown || facts.Package != node.Name {
			continue
		}
		if shown >= 100 {
			b.coverage = append(b.coverage, "package "+node.Name+" stopped at its file budget")
			break
		}
		shown++
		file := b.addFile(path, node.depth+1)
		b.addEdge(node.ID, file.ID, "owns", "package", "high", "")
	}
}

// unitForFile names the unit a unit file or drop-in belongs to.
func unitForFile(path string) string {
	base := filepath.Base(path)
	if hasUnitName(base) {
		return base
	}
	dir := filepath.Base(filepath.Dir(path))
	if strings.HasSuffix(dir, ".d") {
		name := strings.TrimSuffix(dir, ".d")
		if hasUnitName(name) {
			return name
		}
	}
	return ""
}

var unitDirs = []string{
	"/etc/systemd/system",
	"/run/systemd/system",
	"/usr/local/lib/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
}

func findUnitFile(name string) string {
	for _, dir := range unitDirs {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

func shebang(path string) (string, bool) {
	file, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer file.Close()
	buf := make([]byte, 256)
	n, _ := file.Read(buf)
	if n < 3 || buf[0] != '#' || buf[1] != '!' {
		return "", false
	}
	fields := strings.Fields(string(bytes.TrimSpace(buf[2:n])))
	if len(fields) == 0 {
		return "", false
	}
	interpreter := fields[0]
	if filepath.Base(interpreter) == "env" && len(fields) > 1 {
		name := fields[1]
		for _, dir := range []string{"/usr/bin", "/bin", "/usr/local/bin"} {
			candidate := filepath.Join(dir, name)
			if _, err := os.Stat(candidate); err == nil {
				return candidate, true
			}
		}
		return "", false
	}
	if !filepath.IsAbs(interpreter) {
		return "", false
	}
	return interpreter, true
}

func isShellScript(path string, facts trust.Facts) bool {
	if !facts.Executable {
		return false
	}
	if strings.HasSuffix(filepath.Base(path), ".sh") {
		return true
	}
	interpreter, ok := shebang(path)
	if !ok {
		return false
	}
	switch filepath.Base(interpreter) {
	case "bash", "sh", "dash", "zsh", "ksh", "fish":
		return true
	}
	return false
}

func isELF(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	var magic [4]byte
	if _, err := io.ReadFull(file, magic[:]); err != nil {
		return false
	}
	return bytes.Equal(magic[:], []byte{0x7f, 'E', 'L', 'F'})
}

func readFileCapped(path string, limit int64) ([]byte, bool) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit))
	if err != nil {
		return nil, false
	}
	return data, true
}

func isText(data []byte) bool {
	probe := data
	if len(probe) > 8192 {
		probe = probe[:8192]
	}
	return bytes.IndexByte(probe, 0) < 0
}

// isAppPath reports a trees where an unowned application usually lives. Their
// containment is the application tree rather than a package.
func isAppPath(path string) bool {
	for _, root := range []string{"/opt/", "/srv/", "/usr/local/", "/home/", "/root/", "/var/www/", "/var/lib/"} {
		if strings.HasPrefix(path, root) {
			return true
		}
	}
	return false
}

func appRoot(path string) string {
	for _, prefix := range []string{"/opt/", "/srv/", "/usr/local/", "/home/", "/var/www/", "/var/lib/"} {
		rest, ok := strings.CutPrefix(path, prefix)
		if !ok {
			continue
		}
		parts := strings.Split(rest, "/")
		if len(parts) < 2 {
			return ""
		}
		return filepath.Join(prefix, parts[0])
	}
	return ""
}

func isConfigPath(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".conf", ".cfg", ".ini", ".toml", ".yaml", ".yml", ".json",
		".properties", ".env", ".xml", ".jar", ".sh", ".py", ".pl", ".rb":
		return true
	}
	return strings.HasPrefix(path, "/etc/")
}

func cmdlinePaths(cmdline string) []string {
	fields := strings.Fields(cmdline)
	var out []string
	seen := map[string]bool{}
	add := func(value string) {
		value = strings.Trim(value, `"'`)
		if value == "" || !filepath.IsAbs(value) {
			return
		}
		value = filepath.Clean(value)
		if seen[value] {
			return
		}
		seen[value] = true
		out = append(out, value)
	}
	flags := map[string]bool{
		"--config": true, "-c": true, "--conf": true, "--settings": true,
		"--properties": true, "--file": true, "-f": true, "--env-file": true,
		"--spring.config.additional-location": true, "--spring.config.location": true,
	}
	for index := 0; index < len(fields); index++ {
		field := strings.Trim(fields[index], `"'`)
		name, value, has := strings.Cut(field, "=")
		if has {
			if flags[name] || isConfigPath(value) {
				add(value)
			}
			continue
		}
		if flags[name] && index+1 < len(fields) {
			add(fields[index+1])
			index++
			continue
		}
		if filepath.IsAbs(field) && (isConfigPath(field) || strings.HasSuffix(field, ".jar") || strings.HasSuffix(field, ".sh")) {
			add(field)
		}
	}
	return out
}

func openFiles(pid int) []string {
	dir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(dir, entry.Name()))
		if err != nil || !strings.HasPrefix(target, "/") {
			continue
		}
		target = strings.TrimSuffix(target, " (deleted)")
		if seen[target] {
			continue
		}
		info, err := os.Stat(target)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		seen[target] = true
		out = append(out, target)
	}
	return out
}

func mappedFiles(pid int) []string {
	file, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "maps"))
	if err != nil {
		return nil
	}
	defer file.Close()
	seen := map[string]bool{}
	var out []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		space := strings.LastIndexByte(line, ' ')
		if space < 0 {
			continue
		}
		path := strings.TrimSpace(line[space+1:])
		path = strings.TrimSuffix(path, " (deleted)")
		if !strings.HasPrefix(path, "/") || seen[path] {
			continue
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	return out
}

// interestingContext keeps the open/mapped scan to files that change a
// program's behavior: configuration, scripts, archives and unowned app files.
// Package-owned shared libraries are package evidence, not process evidence.
func interestingContext(path string, process Process) bool {
	if path == process.Exe || path == process.Script {
		return false
	}
	if strings.HasSuffix(path, ".so") || strings.Contains(path, ".so.") {
		return false
	}
	if isConfigPath(path) || strings.HasSuffix(strings.ToLower(path), ".jar") {
		return true
	}
	if isAppPath(path) {
		if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o111 != 0 {
			return true
		}
		return false
	}
	for _, prefix := range []string{"/proc/", "/sys/", "/dev/", "/usr/lib/", "/lib/", "/usr/share/"} {
		if strings.HasPrefix(path, prefix) {
			return false
		}
	}
	return false
}
