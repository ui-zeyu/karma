package audit

// The discovery half of the object graph: what one node pulls in — ELF and
// JAR dependencies, shell and lexical path references, application-tree
// containment, a process's open and mapped files — and the file-shape
// predicates they share.

import (
	"archive/zip"
	"bufio"
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"karma/internal/trust"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"karma/internal/localfs"
	"karma/internal/startup"
)

func (b *graphBuilder) expandFile(node *GraphNode) {
	path := node.Path
	if path == "" || node.Missing {
		return
	}
	facts := b.snapshot.Facts(path)
	if facts.Kind != trust.File {
		// A directory, FIFO, device or socket has no readable content body.
		// Refusing it here keeps every content parser below on a regular file
		// even when the path was planted after the facts were read.
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
	// One read answers every shape question: the shebang, the script test,
	// the text probe and the ELF magic all read the same bytes.
	if data, ok := readFileCapped(path, objectBinBytes); ok {
		if interpreter, ok := shebangOf(data); ok {
			interp := b.addFile(interpreter, node.depth+1)
			b.addEdge(node.ID, interp.ID, "interpreter", "shebang", "high", "")
		}
		if isShellScript(path, facts, data) {
			b.shellRefs(node)
		}
		probe := data
		if len(probe) > objectTextBytes {
			probe = probe[:objectTextBytes]
		}
		if isText(probe) {
			b.lexicalRefs(node, probe, "lexical")
		} else if facts.Executable {
			b.lexicalRefs(node, data, "strings")
		}
		if facts.Executable && isELFData(data) {
			b.elfRefs(node)
		}
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
	// One past the budget tells a stop from a short scan.
	paths := extractPaths(data, objectMaxLexical+1)
	if len(paths) > objectMaxLexical {
		paths = paths[:objectMaxLexical]
		b.coverage = append(b.coverage, coverageGap("graph", "lexical scan of "+node.Path+" stopped at its path budget"))
	}
	for _, path := range paths {
		if path == node.Path {
			continue
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		target := b.addFile(path, node.depth+1)
		b.addEdge(node.ID, target.ID, "mentions", source, "low", "path string in content")
	}
}

// extractPaths reads the path-shaped tokens a text carries, in the order the
// scan finds them. The limit stops the scan, so a path-dense file costs its
// budget instead of a materialized match for every token in two megabytes.
func extractPaths(data []byte, limit int) []string {
	var out []string
	seen := map[string]bool{}
	for _, match := range pathTokenRE.FindAll(data, -1) {
		if len(out) >= limit {
			break
		}
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
	raw, err := localfs.Open(node.Path)
	if err != nil {
		return
	}
	defer raw.Close()
	file, err := elf.NewFile(raw)
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
	raw, err := localfs.Open(node.Path)
	if err != nil {
		return
	}
	defer raw.Close()
	info, err := raw.Stat()
	if err != nil {
		return
	}
	reader, err := zip.NewReader(raw, info.Size())
	if err != nil {
		return
	}
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
	dir := b.addDir(root, node.depth+1)
	dir.Context = true
	if dir.Detail == "" {
		dir.Detail = "application tree"
	} else {
		dir.Detail = "application tree · " + dir.Detail
	}
	dir.Discovered = true
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
			b.coverage = append(b.coverage, coverageGap("graph", "application tree "+root+" stopped at its file budget"))
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
	paths := cmdlinePathArgs(process.Args)
	if len(paths) == 0 {
		paths = cmdlinePaths(process.Cmdline)
	}
	for _, path := range paths {
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
		if connection.PID != pid && !slices.Contains(connection.PIDs, pid) {
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
		if node.typedOrigin() == Unknown {
			node.setOrigin(trigger.typedOrigin())
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
				Class: "unit-target-missing", Severity: Medium, Origin: Unknown, Reach: RootAsset,
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
		if path := startup.LookupUnitFile(name); path != "" {
			file := b.addFile(path, node.depth+1)
			b.addEdge(node.ID, file.ID, "configured-by", "unit", "high", "")
			if node.typedOrigin() == Unknown {
				node.setOrigin(file.typedOrigin())
				node.Detail = file.Detail
			}
			b.enqueue(file.ID)
		} else {
			b.coverage = append(b.coverage, coverageGap("graph", "unit "+name+" has no readable unit file or activation edge"))
		}
	}
	// Drop-ins exist even when the unit has no ExecStart edge of its own.
	for _, dir := range startup.UnitDirs() {
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

// objectMaxPackageFiles is the file budget one package expansion shows. The
// walk takes the paths in sorted order, so the same run answers the same
// graph twice — the graph is evidence, and evidence must reproduce.
const objectMaxPackageFiles = 100

func (b *graphBuilder) expandPackage(node *GraphNode) {
	var paths []string
	for path, facts := range b.snapshot.Objects {
		if facts.PackageKnown && facts.Package == node.Name {
			paths = append(paths, path)
		}
	}
	slices.Sort(paths)
	if shown := len(paths); shown > objectMaxPackageFiles {
		b.coverage = append(b.coverage, coverageGap("graph",
			fmt.Sprintf("package %s stopped at its file budget: %d more file(s) than the graph shows",
				node.Name, shown-objectMaxPackageFiles)))
		paths = paths[:objectMaxPackageFiles]
	}
	for _, path := range paths {
		file := b.addFile(path, node.depth+1)
		b.addEdge(node.ID, file.ID, "owns", "package", "high", "")
	}
}

// unitForFile names the unit a unit file or drop-in belongs to, or "" when
// the path is neither.
func unitForFile(path string) string {
	name := activationUnit(path)
	if startup.IsUnitName(name) {
		return name
	}
	return ""
}

// shebangOf reads the interpreter a file's first line names, from bytes the
// caller already holds.
func shebangOf(buf []byte) (string, bool) {
	if len(buf) > 256 {
		buf = buf[:256]
	}
	n := len(buf)
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

func isShellScript(path string, facts trust.Facts, data []byte) bool {
	if !facts.Executable {
		return false
	}
	if strings.HasSuffix(filepath.Base(path), ".sh") {
		return true
	}
	interpreter, ok := shebangOf(data)
	if !ok {
		return false
	}
	switch filepath.Base(interpreter) {
	case "bash", "sh", "dash", "zsh", "ksh", "fish":
		return true
	}
	return false
}

func isELFData(data []byte) bool {
	return len(data) >= 4 && bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'})
}

func readFileCapped(path string, limit int64) ([]byte, bool) {
	data, err := localfs.ReadFile(path, limit)
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

// appRoots are the trees an application installs into. Root's home answers
// isAppPath — administrators keep tools there — and is excluded from
// appRoot: containment walks an application tree, and /root is also where
// one-off operator files live.
var appRoots = []string{"/opt/", "/srv/", "/usr/local/", "/home/", "/root/", "/var/www/", "/var/lib/"}

func isAppPath(path string) bool {
	for _, root := range appRoots {
		if strings.HasPrefix(path, root) {
			return true
		}
	}
	return false
}

func appRoot(path string) string {
	for _, prefix := range appRoots {
		if prefix == "/root/" {
			continue
		}
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
	return cmdlinePathArgs(strings.Fields(cmdline))
}

func cmdlinePathArgs(fields []string) []string {
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
