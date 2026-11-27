package audit

// An object graph is one object's relation graph: what the unit, process or
// file declares, what the kernel observes, what its package owns, what sits
// in its installation tree, and which paths its content mentions. Edges
// carry the source that produced them and a confidence, so a kernel
// observation and a lexical lead do not read alike.

import (
	"context"
	"fmt"
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
	kind, value := seedKind(""), word
	switch {
	case strings.HasPrefix(word, "unit:"):
		kind, value = seedUnit, strings.TrimPrefix(word, "unit:")
	case strings.HasPrefix(word, "pid:"):
		kind, value = seedPid, strings.TrimPrefix(word, "pid:")
	case strings.HasPrefix(word, "path:"):
		kind, value = seedPath, strings.TrimPrefix(word, "path:")
	case strings.HasPrefix(word, "pkg:"):
		kind, value = seedPackage, strings.TrimPrefix(word, "pkg:")
	case strings.HasPrefix(word, "/"):
		kind = seedPath
	case isDigits(word):
		kind = seedPid
	case startup.IsUnitName(word):
		kind = seedUnit
	default:
		kind = seedPackage
	}
	switch kind {
	case seedUnit:
		if value == "" {
			return GraphSeed{}, fmt.Errorf("graph: empty unit name")
		}
	case seedPid:
		if _, err := strconv.Atoi(value); err != nil {
			return GraphSeed{}, fmt.Errorf("graph: %q is not a pid", value)
		}
	case seedPath:
		if !filepath.IsAbs(value) {
			return GraphSeed{}, fmt.Errorf("graph: %q is not an absolute path", value)
		}
	case seedPackage:
		if value == "" {
			return GraphSeed{}, fmt.Errorf("graph: empty package name")
		}
	}
	return GraphSeed{Kind: kind, Value: value}, nil
}

// GraphView is one object's evidence graph.

// GraphView is the graph one object grew into. Its JSON contract is stated
// once, in WriteGraphJSON — the only encoder of this view — so the two can
// never disagree about a field name.
type GraphView struct {
	Root     string
	RootKind string
	Boundary Boundary
	Nodes    []GraphNode
	Edges    []GraphEdge
	Findings []Finding
	Coverage []Coverage
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

	depth int
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
	ctx        context.Context
	snapshot   *Snapshot
	assessor   *assessor
	graph      *GraphBuilder
	queue      []string
	expanded   map[string]bool
	processes  map[int]Process
	trees      map[string]bool
	reverse    bool // a path seed reads the objects that name it
	findings   []Finding
	coverage   []Coverage
	skippedFD  int
	skippedMap int
	skippedLib int
	dynamic    int
	budget     int
}

// BuildObjectGraph walks one object's relation closure over the snapshot.
// BuildObjectGraph grows one object's relation graph and attaches its
// findings. The judgment runs once here, at the package boundary — the
// builder itself never judges; it only collects the closure.

func BuildObjectGraph(ctx context.Context, snapshot *Snapshot, seed GraphSeed) (*GraphView, error) {
	view, err := buildObjectGraph(ctx, snapshot, seed)
	if err != nil {
		return nil, err
	}
	view.AttachObjectFindings(snapshot, Judge(snapshot, snapshot.plan.Filter))
	return view, nil
}

func buildObjectGraph(ctx context.Context, snapshot *Snapshot, seed GraphSeed) (*GraphView, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("graph: no snapshot")
	}
	b := &graphBuilder{
		ctx: ctx, snapshot: snapshot, assessor: snapshot.Assessor(),
		graph:    &GraphBuilder{nodes: map[string]*GraphNode{}, edgeSeen: map[string]bool{}},
		expanded: map[string]bool{}, processes: map[int]Process{},
		trees: map[string]bool{}, budget: objectMaxNodes,
	}
	for _, process := range snapshot.Processes {
		b.processes[process.PID] = process
	}
	root, err := b.seed(seed)
	if err != nil {
		return nil, err
	}
	b.graph.setRoot(root)
	b.queue = append(b.queue, root)
	for len(b.queue) > 0 {
		if err := ctx.Err(); err != nil {
			b.coverage = append(b.coverage, coverageAbsent("graph", "graph stopped: "+err.Error()))
			break
		}
		if b.budget == 0 {
			b.coverage = append(b.coverage, coverageGap("graph", "graph stopped at its node budget"))
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
	// The seed findings the walk collected attach here; the report's findings
	// join through AttachObjectFindings once the caller has run one judgment.
	view.Findings = b.findings
	if b.skippedFD > 0 {
		b.coverage = append(b.coverage, Coverage{
			Area: "graph", Status: CoverageDegraded, Count: b.skippedFD,
			Detail: fmt.Sprintf("%d open file(s) skipped as package-owned base context", b.skippedFD),
		})
	}
	if b.skippedMap > 0 {
		b.coverage = append(b.coverage, Coverage{
			Area: "graph", Status: CoverageDegraded, Count: b.skippedMap,
			Detail: fmt.Sprintf("%d mapped file(s) skipped as package-owned base context", b.skippedMap),
		})
	}
	if b.skippedLib > 0 {
		b.coverage = append(b.coverage, Coverage{
			Area: "graph", Status: CoverageDegraded, Count: b.skippedLib,
			Detail: fmt.Sprintf("%d linked library(ies) are package-owned base files", b.skippedLib),
		})
	}
	if b.dynamic > 0 {
		b.coverage = append(b.coverage, Coverage{
			Area: "graph", Status: CoverageDegraded, Count: b.dynamic,
			Detail: fmt.Sprintf("%d reference(s) were dynamic and could not be resolved statically", b.dynamic),
		})
	}
	coverage := append([]Coverage(nil), b.snapshot.Coverage...)
	coverage = append(coverage, b.coverage...)
	view.Coverage = uniqueCoverage(coverage)
	return view
}

// AttachObjectFindings trims one full report to the objects the graph grew,
// and adds the scoped counterpart of the static inventory's unowned-file: a
// runtime executable the walk selected or discovered that neither an
// activation edge nor a running process explains.

func (p *GraphView) AttachObjectFindings(snapshot *Snapshot, report *Report) {
	paths := map[string]bool{}
	for index := range p.Nodes {
		if p.Nodes[index].Path != "" {
			paths[p.Nodes[index].Path] = true
		}
	}
	activationTargets := map[string]bool{}
	for _, edge := range snapshot.Activations {
		if !edge.Dynamic {
			activationTargets[edge.Target] = true
		}
	}
	a := snapshot.Assessor()
	var out []Finding
	covered := map[string]bool{}
	for _, finding := range report.Findings {
		if paths[finding.Path] {
			out = append(out, finding)
			covered[finding.Path] = true
		}
	}
	// A selected or discovered runtime executable with no package is dormant
	// code the activation and process checks never see.
	for index := range p.Nodes {
		node := &p.Nodes[index]
		if node.Kind != "file" || node.Path == "" || node.Missing || covered[node.Path] || activationTargets[node.Path] {
			continue
		}
		facts := snapshot.Facts(node.Path)
		if !facts.PackageKnown || facts.Package != "" || !facts.Executable {
			continue
		}
		story := a.read(facts)
		if !story.origin.arrived() {
			continue
		}
		severity, reach := unownedFileSeverity(story, facts.RootOwned)
		evidence := append([]string{
			"no package's file list records this path",
			"the file was selected or discovered by the graph",
		}, node.Evidence...)
		out = append(out, Finding{
			Class: "unowned-file", Severity: severity, Origin: story.origin, Reach: reach,
			Title:    "runtime executable no package owns",
			Path:     node.Path,
			Detail:   "it is neither an activation target nor a running process; the graph found it",
			Evidence: evidence,
		})
		covered[node.Path] = true
	}
	out = append(out, p.Findings...)
	sortFindings(out)
	p.Findings = out
}

// addNode registers one node and keeps insertion order for the tree.

func (n *GraphNode) setOrigin(origin Origin) {
	n.Origin = origin.String()
}

// typedOrigin reads the one origin field the graph carries. Display and
// judgment share it, so there is no second state to drift.

func (n *GraphNode) typedOrigin() Origin {
	if n.Origin == "" {
		return Unknown
	}
	origin, _ := originByName(n.Origin)
	return origin
}

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
	if node := b.graph.node(nodeKey("file", path)); node != nil {
		return node
	}
	if node := b.graph.node(nodeKey("dir", path)); node != nil {
		return node
	}
	b.snapshot.ensureFacts([]string{path})
	facts := b.snapshot.Facts(path)
	story := b.assessor.read(facts)
	kind := "file"
	if facts.Kind == trust.Dir {
		kind = "dir"
	}
	id := nodeKey(kind, path)
	node := &GraphNode{
		ID: id, Kind: kind, Name: filepath.Base(path), Path: path,
		Origin: story.origin.String(),
		Detail: story.why, Evidence: story.evidence, depth: depth,
		Discovered: depth > 0,
	}
	if facts.Kind == trust.Missing {
		node.Missing = true
		node.Detail = "missing"
	}
	if content, ok := b.snapshot.Verify[facts.Real]; ok {
		copied := content
		node.Content = &copied
	}
	if facts.PackageKnown && facts.Package != "" {
		pkg := b.addPackage(facts.Package, depth+1)
		b.addEdge(id, pkg.ID, "owned-by", "package", "high", "")
	} else if facts.PackageKnown && facts.Package == "" && node.Detail == "" {
		// The story already carries the nearest-owned-ancestor sentence.
		node.Detail = "no package owns it"
	}
	if facts.Setuid || facts.Caps {
		node.Reach = RootAsset.String()
	}
	return b.addNode(node)
}

// NearestOwner on the snapshot answers the closest owned ancestor; the walk
// reads ancestors the collection did not judge and the assessor quotes the
// same tree, so there is one nearest-owned-ancestor implementation.

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
	imageStory := b.assessor.read(process.ExeFacts)
	origin := imageStory.origin
	evidence := append([]string(nil), imageStory.evidence...)
	if process.Script != "" {
		scriptStory := b.assessor.read(process.ScriptFacts)
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
		Origin: origin.String(), Reach: reach.String(),
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
	node := b.addFile(path, depth)
	node.Context = true
	return node
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

var pathTokenRE = regexp.MustCompile(`(?:^|[\s"'=:(,;])/(?:[A-Za-z0-9._+\-@%]+/)*[A-Za-z0-9._+\-@%]+`)
