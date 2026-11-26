package audit

// The kernel domain reads what the running kernel says about itself and what
// the dynamic loader searches. A loaded module is still an artifact: its .ko
// file is judged by the same origin and reach as every other object, and the
// module registries are compared because a rootkit can scrub one of them but
// rarely all three. Hidden pids are the process-side counterpart: the kernel's
// pid space is asked directly, without trusting the directory listing.

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"karma/internal/trust"
)

const (
	procModulesPath = "/proc/modules"
	kallsymsPath    = "/proc/kallsyms"
	taintedPath     = "/proc/sys/kernel/tainted"
	pidMaxPath      = "/proc/sys/kernel/pid_max"
	sysModuleDir    = "/sys/module"

	modulesDepLimit = 8 << 20
	kallsymsLimit   = 64 << 20
	configTextLimit = 256 << 10
	loaderScanLimit = 20000

	// hiddenModuleShown and hiddenPIDShown bound a report whose host is under
	// active attack; the rest is a coverage count.
	hiddenModuleShown = 50
	hiddenPIDShown    = 50
	registryGapShown  = 20
	loaderFileShown   = 50
)

// KernelModule file states: mapped names the .ko on disk, missing names a file the
// dependency database records that the disk does not carry, and unmapped
// names a loaded module modules.dep does not name at all.
const (
	ModuleFileMapped   = "mapped"
	ModuleFileMissing  = "missing"
	ModuleFileUnmapped = "unmapped"
	ModuleFileDormant  = "dormant"
)

// KernelModule is one entry of /proc/modules joined to its file and declarations.
type KernelModule struct {
	Name       string   `json:"name"`
	Size       uint64   `json:"size,omitempty"`
	Used       int      `json:"used,omitempty"`
	State      string   `json:"state,omitempty"`
	Taint      string   `json:"taint,omitempty"`
	File       string   `json:"file,omitempty"`
	FileState  string   `json:"file_state,omitempty"`
	InSysfs    bool     `json:"in_sysfs,omitempty"`
	InKallsyms bool     `json:"in_kallsyms,omitempty"`
	Declared   []string `json:"declared,omitempty"`
	// Facts are the module file's filesystem facts; they are judged through
	// the same assessor as every other artifact.
	Facts trust.Facts `json:"-"`
}

// HiddenModule is a module one registry carries while /proc/modules does not.
type HiddenModule struct {
	Name  string   `json:"name"`
	Views []string `json:"views"`
}

// LoaderDir is one directory on the dynamic loader's search path.
type LoaderDir struct {
	Path  string      `json:"path"`
	Facts trust.Facts `json:"-"`
}

// LoaderFile is one shared library inside a loader search directory. It is
// not added to the judged object set: the loader check needs ownership, and
// hashing every package library would turn a cheap graph edge into a full
// content sweep.
type LoaderFile struct {
	Path  string      `json:"path"`
	Facts trust.Facts `json:"-"`
}

// KernelState is what one kernel-domain collection answered.
type KernelState struct {
	Collected    bool           `json:"collected,omitempty"`
	Modules      []KernelModule `json:"modules,omitempty"`
	Dormant      []KernelModule `json:"dormant_modules,omitempty"`
	Hidden       []HiddenModule `json:"hidden_modules,omitempty"`
	RegistryGaps []string       `json:"registry_gaps,omitempty"`
	Tainted      int            `json:"tainted,omitempty"`
	TaintNames   []string       `json:"taint_names,omitempty"`
	// MappingStale reports a modules.dep that names none of the loaded
	// modules: the file database belongs to another kernel, so an unmapped
	// row is not evidence about one module.
	MappingStale     bool         `json:"mapping_stale,omitempty"`
	HiddenPIDs       []int        `json:"hidden_pids,omitempty"`
	DeclarationFiles []string     `json:"declaration_files,omitempty"`
	LoaderConfig     []string     `json:"loader_config,omitempty"`
	LoaderDirs       []LoaderDir  `json:"loader_dirs,omitempty"`
	LoaderFiles      []LoaderFile `json:"-"`
	// Sources are the first meaningful line of each loader or module
	// declaration file, the quote a finding carries.
	Sources map[string]Quote `json:"-"`
}

// moduleRow is one /proc/modules line before the file join.
type moduleRow struct {
	Name  string
	Size  uint64
	Used  int
	State string
	Taint string
}

// collectKernel reads the kernel domain and returns the coverage gaps its
// reads produced. The module files, declaration files and loader configuration
// join snapshot.Objects so the content ledger judges them.
func collectKernel(ctx context.Context, snapshot *Snapshot, facts func(string) trust.Facts, prefetch func([]string)) []string {
	state := &snapshot.Kernel
	if _, err := os.Stat("/proc"); err != nil {
		return []string{"kernel state is only read on Linux"}
	}
	state.Collected = true
	var gaps []string

	declared, declarationFiles, declarationGaps := readModuleDeclarations(snapshot, facts)
	gaps = append(gaps, declarationGaps...)
	state.DeclarationFiles = declarationFiles

	first, firstOK := readProcModules()
	sysfsFirst, sysfsFirstOK := readSysfsModules()
	second, secondOK := readProcModules()
	// Read the cheap sysfs view on both sides of the /proc reads. The
	// intersection excludes a module that unloads during collection; the
	// union of the /proc reads excludes one that loads. The kernel symbol
	// table is expensive, so it is read once at the end and the final /proc
	// read keeps a module that appeared after the second read out of the
	// hidden set.
	sysfsSecond, sysfsSecondOK := readSysfsModules()
	symbols, kallsymsOK := readKallsymsModules(ctx)
	third, thirdOK := readProcModules()
	if !firstOK && !secondOK && !thirdOK {
		gaps = append(gaps, "kernel module registry "+procModulesPath+" is unreadable")
	}
	loaded, order, stable := mergeModuleReads(
		moduleRead{rows: first, ok: firstOK},
		moduleRead{rows: second, ok: secondOK},
		moduleRead{rows: third, ok: thirdOK},
	)
	sysfs, sysfsOK := steadyModuleView(sysfsFirst, sysfsFirstOK, sysfsSecond, sysfsSecondOK)
	builtin, _ := readModulesBuiltin(snapshot.Host.Kernel)
	for name := range builtin {
		delete(symbols, name)
		delete(sysfs, name)
	}

	emptyContainerView := len(loaded) == 0 && snapshot.Boundary.Kind == "container" &&
		(len(sysfs) > 0 || len(symbols) > 0)
	if emptyContainerView {
		// A container runtime can mask /proc/modules while /sys and kallsyms still
		// describe the host kernel. Treating every host module as hidden would be
		// a false storm; the missing list is coverage, not a verdict.
		gaps = append(gaps, "module list is empty in this container; the registry cross-check was skipped")
	} else if firstOK || secondOK || thirdOK {
		loadedNames := make(map[string]bool, len(loaded))
		for name := range loaded {
			loadedNames[name] = true
		}
		hidden, registryGaps, diffGaps := diffModuleViews(stable, loadedNames, sysfs, sysfsOK, symbols, kallsymsOK)
		state.Hidden = hidden
		state.RegistryGaps = registryGaps
		gaps = append(gaps, diffGaps...)
	}

	mapping, mapped := readModulesDep(snapshot.Host.Kernel)
	if !mapped {
		gaps = append(gaps, "module file mapping unavailable: "+filepath.Join("/lib/modules", snapshot.Host.Kernel, "modules.dep"))
	}
	var moduleFiles []string
	mappedCount := 0
	for _, name := range order {
		file, ok := mapping[normalizeModuleName(name)]
		if !ok {
			continue
		}
		mappedCount++
		moduleFiles = append(moduleFiles, file)
		// The package database records the usrmerge spelling; the module
		// database can name the /lib spelling. Prefetch both so Classify's
		// resolved query is a cache hit rather than one dpkg call per module.
		if real, err := filepath.EvalSymlinks(file); err == nil && real != file {
			moduleFiles = append(moduleFiles, real)
		}
	}
	if mapped && len(order) > 0 && mappedCount == 0 {
		state.MappingStale = true
		gaps = append(gaps, "module database names no loaded module: the file mapping belongs to another kernel")
	}
	prefetch(moduleFiles)

	for _, name := range order {
		row := loaded[name]
		module := KernelModule{
			Name: row.Name, Size: row.Size, Used: row.Used, State: row.State, Taint: row.Taint,
			InSysfs: sysfs[name], InKallsyms: symbols[name], Declared: declared[row.Name],
		}
		if mapped {
			file, ok := mapping[normalizeModuleName(row.Name)]
			if !ok {
				module.FileState = ModuleFileUnmapped
			} else {
				module.File = file
				module.Facts = facts(file)
				if module.Facts.Kind == trust.File {
					module.FileState = ModuleFileMapped
				} else {
					module.FileState = ModuleFileMissing
				}
				remember(snapshot, file, module.Facts)
			}
		}
		state.Modules = append(state.Modules, module)
	}
	dormantGaps := collectDormantModules(snapshot, state, facts, prefetch)
	gaps = append(gaps, dormantGaps...)

	state.Tainted, state.TaintNames = readTaint()
	if state.Tainted != 0 {
		gaps = append(gaps, fmt.Sprintf("kernel taint mask %d: %s", state.Tainted, strings.Join(state.TaintNames, ", ")))
	}

	hiddenPIDs, pidGaps := readHiddenPIDs(ctx)
	state.HiddenPIDs = hiddenPIDs
	gaps = append(gaps, pidGaps...)

	loaderGaps := collectLoader(ctx, state, snapshot, facts, prefetch)
	gaps = append(gaps, loaderGaps...)
	return gaps
}

// moduleRead is one /proc/modules read and whether the file answered.
type moduleRead struct {
	rows []moduleRow
	ok   bool
}

// mergeModuleReads unions the /proc/modules reads. The first read fixes the
// order; a module that appeared later is appended. The stable set is what
// every successful read carried, and only that set may be called a gap in
// sysfs: a module loading during the collection is a race, not evidence.
func mergeModuleReads(reads ...moduleRead) (map[string]moduleRow, []string, map[string]bool) {
	loaded := map[string]moduleRow{}
	var order []string
	counts := map[string]int{}
	usable := 0
	for _, read := range reads {
		if !read.ok {
			continue
		}
		usable++
		for _, row := range read.rows {
			counts[row.Name]++
			if _, seen := loaded[row.Name]; !seen {
				loaded[row.Name] = row
				order = append(order, row.Name)
			}
		}
	}
	stable := map[string]bool{}
	if usable > 0 {
		for name, count := range counts {
			if count == usable {
				stable[name] = true
			}
		}
	}
	return loaded, order, stable
}

// steadyModuleView intersects the two sysfs reads so a module that unloads
// between them is not called hidden. A single readable view carries the answer
// when the other failed.
func steadyModuleView(first map[string]bool, firstOK bool, second map[string]bool, secondOK bool) (map[string]bool, bool) {
	switch {
	case firstOK && secondOK:
		steady := map[string]bool{}
		for name := range first {
			if second[name] {
				steady[name] = true
			}
		}
		return steady, true
	case firstOK:
		return first, true
	case secondOK:
		return second, true
	default:
		return nil, false
	}
}

// readProcModules reads /proc/modules. ok is false only when the file could
// not be read; an empty file is a host with no loadable modules.
func readProcModules() ([]moduleRow, bool) {
	data, err := os.ReadFile(procModulesPath)
	if err != nil {
		return nil, false
	}
	return parseProcModules(string(data)), true
}

// parseProcModules reads the kernel module registry: name, size, refcount,
// dependencies, state, address, and the taint flags in parentheses.
func parseProcModules(text string) []moduleRow {
	var rows []moduleRow
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		size, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		used, _ := strconv.Atoi(fields[2])
		row := moduleRow{Name: normalizeModuleName(fields[0]), Size: size, Used: used, State: fields[4]}
		if len(fields) >= 7 {
			row.Taint = strings.Trim(fields[6], "()")
			if row.Taint == "-" {
				row.Taint = ""
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// readSysfsModules reads the loader's own registry. Built-in modules have a
// /sys/module directory too; only a loadable module has a sections/
// subdirectory, and that is the entry the cross-check counts.
func readSysfsModules() (map[string]bool, bool) {
	entries, err := os.ReadDir(sysModuleDir)
	if err != nil {
		return nil, false
	}
	modules := map[string]bool{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		sections := filepath.Join(sysModuleDir, entry.Name(), "sections")
		if info, err := os.Stat(sections); err == nil && info.IsDir() {
			modules[normalizeModuleName(entry.Name())] = true
		}
	}
	return modules, true
}

// readKallsymsModules reads the module tag every symbol carries. A module
// cannot scrub its symbols without unloading, so this view survives a scrub
// of /proc/modules and /sys/module.
func readKallsymsModules(ctx context.Context) (map[string]bool, bool) {
	file, err := os.Open(kallsymsPath)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	modules := map[string]bool{}
	reader := bufio.NewReaderSize(file, 1<<20)
	var read int
	for {
		if err := ctx.Err(); err != nil {
			return modules, true
		}
		line, err := reader.ReadString('\n')
		read += len(line)
		line = strings.TrimSuffix(line, "\n")
		if open := strings.LastIndexByte(line, '['); open >= 0 && strings.HasSuffix(line, "]") {
			name := normalizeModuleName(line[open+1 : len(line)-1])
			// [bpf] tags the kernel's JIT images, not a loadable module.
			if name != "" && name != "bpf" && !strings.ContainsAny(name, " \t") {
				modules[name] = true
			}
		}
		if err == io.EOF {
			return modules, true
		}
		if err != nil {
			return modules, true
		}
		if read > kallsymsLimit {
			return modules, true
		}
	}
}

// diffModuleViews reports the names the registries disagree about. A name in
// sysfs or kallsyms that neither /proc/modules read carried is hidden; only a
// module both /proc reads carried is allowed to be a gap in sysfs.
func diffModuleViews(stable, loaded, sysfs map[string]bool, sysfsOK bool, symbols map[string]bool, kallsymsOK bool) ([]HiddenModule, []string, []string) {
	var gaps []string
	if sysfsOK && len(sysfs) == 0 && len(stable) > 0 {
		// Some container runtimes expose /sys without the module registry;
		// an empty view would turn every loaded module into a gap.
		gaps = append(gaps, "sysfs module registry is empty; the registry cross-check was skipped")
		sysfsOK = false
	}
	views := map[string][]string{}
	if sysfsOK {
		for name := range sysfs {
			if !loaded[name] {
				views[name] = append(views[name], "sysfs")
			}
		}
	}
	if kallsymsOK {
		for name := range symbols {
			if !loaded[name] {
				views[name] = append(views[name], "kallsyms")
			}
		}
	}
	// A module can appear in both views with the same name; one entry per
	// name, with the views that carry it.
	var hidden []HiddenModule
	for name, seen := range views {
		sort.Strings(seen)
		hidden = append(hidden, HiddenModule{Name: name, Views: seen})
	}
	sort.Slice(hidden, func(i, j int) bool { return hidden[i].Name < hidden[j].Name })
	if len(hidden) > hiddenModuleShown {
		gaps = append(gaps, fmt.Sprintf("%d more hidden module(s) than the report shows", len(hidden)-hiddenModuleShown))
		hidden = hidden[:hiddenModuleShown]
	}
	var registryGaps []string
	if sysfsOK {
		for name := range stable {
			if !sysfs[name] {
				registryGaps = append(registryGaps, name)
			}
		}
		sort.Strings(registryGaps)
		if len(registryGaps) > registryGapShown {
			gaps = append(gaps, fmt.Sprintf("%d more module registry gap(s) than the report shows", len(registryGaps)-registryGapShown))
			registryGaps = registryGaps[:registryGapShown]
		}
	}
	return hidden, registryGaps, gaps
}

// readModulesDep maps a loaded module's name to the .ko file the module
// database records. The module manager normalizes '-' to '_'; the map does
// the same on both sides.
func readModulesDep(release string) (map[string]string, bool) {
	if release == "" {
		return nil, false
	}
	for _, root := range []string{"/lib/modules", "/usr/lib/modules"} {
		dir := filepath.Join(root, release)
		data, err := readCapped(filepath.Join(dir, "modules.dep"), modulesDepLimit)
		if err != nil {
			continue
		}
		return parseModulesDep(string(data), dir), true
	}
	return nil, false
}

// readModulesBuiltin names the modules compiled into the running kernel.
// They appear in /sys/module and kallsyms without a /proc/modules row, so the
// hidden-module comparison subtracts them first.
func readModulesBuiltin(release string) (map[string]bool, bool) {
	if release == "" {
		return nil, false
	}
	for _, root := range []string{"/lib/modules", "/usr/lib/modules"} {
		data, err := readCapped(filepath.Join(root, release, "modules.builtin"), modulesDepLimit)
		if err != nil {
			continue
		}
		builtin := map[string]bool{}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			name := normalizeModuleName(strings.TrimSuffix(filepath.Base(line), filepath.Ext(line)))
			if name != "" {
				builtin[name] = true
			}
		}
		return builtin, true
	}
	return nil, false
}

// parseModulesDep reads `relative/path.ko: dependency...` rows.
func parseModulesDep(text, dir string) map[string]string {
	mapping := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		file, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		file = strings.TrimSpace(file)
		if file == "" {
			continue
		}
		name := moduleName(filepath.Base(file))
		if name == "" {
			continue
		}
		mapping[name] = filepath.Join(dir, file)
	}
	return mapping
}

// moduleName reads a module name out of a module file name, dropping the
// compression suffix and the .ko extension.
func moduleName(file string) string {
	for _, suffix := range []string{".xz", ".gz", ".zst", ".lz4"} {
		file = strings.TrimSuffix(file, suffix)
	}
	if !strings.HasSuffix(file, ".ko") {
		return ""
	}
	return normalizeModuleName(strings.TrimSuffix(file, ".ko"))
}

// normalizeModuleName is the kernel's spelling: '-' and '_' name the same
// module.
func normalizeModuleName(name string) string {
	return strings.ReplaceAll(name, "-", "_")
}

// readModuleDeclarations reads the boot module lists. A declaration file is a
// TCB object: it decides which modules load as root.
func readModuleDeclarations(snapshot *Snapshot, facts func(string) trust.Facts) (map[string][]string, []string, []string) {
	var files []string
	declared := map[string][]string{}
	files = append(files, "/etc/modules")
	matches, _ := filepath.Glob("/etc/modules-load.d/*.conf")
	files = append(files, matches...)
	var paths []string
	var gaps []string
	for _, path := range files {
		data, err := readCapped(path, configTextLimit)
		if err != nil {
			continue
		}
		paths = append(paths, path)
		remember(snapshot, path, facts(path))
		if quote, ok := sourceQuote(path, data); ok {
			quoteInto(&snapshot.Kernel, path, quote)
		}
		for _, row := range parseModuleDeclarations(string(data)) {
			declared[row.Name] = append(declared[row.Name], fmt.Sprintf("%s:%d", path, row.Line))
		}
	}
	if len(paths) == 0 {
		gaps = append(gaps, "no boot module declaration file was readable (/etc/modules, /etc/modules-load.d)")
	}
	return declared, paths, gaps
}

// moduleDeclaration is one module named by a boot module list.
type moduleDeclaration struct {
	Name string
	Line int
}

// parseModuleDeclarations reads one boot module list: one module name per
// line, with comments and any option fields after the name ignored.
func parseModuleDeclarations(text string) []moduleDeclaration {
	var rows []moduleDeclaration
	for index, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if cut := strings.IndexByte(line, '#'); cut >= 0 {
			line = strings.TrimSpace(line[:cut])
		}
		if line == "" {
			continue
		}
		name := normalizeModuleName(strings.Fields(line)[0])
		if !validModuleToken(name) {
			continue
		}
		rows = append(rows, moduleDeclaration{Name: name, Line: index + 1})
	}
	return rows
}

// validModuleToken keeps a declaration line's first word from becoming a
// module name when it is an option or a path.
func validModuleToken(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
		default:
			return false
		}
	}
	return true
}

// quoteInto stores one config source line, allocating the map on first use.
func quoteInto(state *KernelState, path string, quote Quote) {
	if state.Sources == nil {
		state.Sources = map[string]Quote{}
	}
	state.Sources[path] = quote
}

// kernelQuotes cites the configuration line behind a loader or module-list
// finding.
func kernelQuotes(state *KernelState, path string) []Quote {
	if quote, ok := state.Sources[path]; ok {
		return []Quote{quote}
	}
	return nil
}

// sourceQuote reads the first meaningful line of a configuration file: the
// first non-empty line outside a comment, within the first 4 KiB.
func sourceQuote(path string, data []byte) (Quote, bool) {
	if len(data) > 4<<10 {
		data = data[:4<<10]
	}
	for index, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return Quote{Path: path, Line: index + 1, Text: line}, true
	}
	return Quote{}, false
}

// readCapped reads at most limit bytes of a file.
func readCapped(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, limit))
}

// readTaint decodes the kernel taint mask. Every set bit is named; the judge
// decides which names are evidence of an operation rather than stock
// out-of-tree noise.
func readTaint() (int, []string) {
	data, err := os.ReadFile(taintedPath)
	if err != nil {
		return 0, nil
	}
	mask, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, nil
	}
	return mask, taintNames(mask)
}

// taintTable is the kernel's taint bit vocabulary.
var taintTable = []string{
	"proprietary module", "forced module load", "cpu out of specification",
	"forced module unload", "machine check", "bad page", "user requested",
	"kernel died", "acpi table overridden", "warning", "staging driver",
	"firmware workaround", "out-of-tree module", "unsigned module",
	"softlockup", "livepatch", "auxiliary taint", "randstruct", "test taint",
}

func taintNames(mask int) []string {
	var names []string
	for bit, name := range taintTable {
		if mask&(1<<bit) != 0 {
			names = append(names, name)
		}
	}
	return names
}

// pidMax reads the kernel's pid ceiling.
func pidMax() int {
	data, err := os.ReadFile(pidMaxPath)
	if err != nil {
		return 0
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || value < 2 {
		return 0
	}
	return value
}

// readHiddenPIDs asks the kernel directly whether a pid exists and compares
// the answer with two /proc listings. A pid absent from both listings while
// kill(0) sees it is hidden from getdents: the process's directory entry was
// scrubbed while the kernel still schedules it.
func readHiddenPIDs(ctx context.Context) ([]int, []string) {
	if hidepid := procHidePIDs(); hidepid > 0 && os.Geteuid() != 0 {
		return nil, []string{fmt.Sprintf("process space not scanned: /proc is mounted with hidepid=%d and this run is not root", hidepid)}
	}
	before, ok := procPIDs()
	if !ok {
		return nil, []string{"process space unreadable: /proc could not be listed"}
	}
	limit := pidCeiling(before)
	if limit == 0 {
		return nil, []string{"process space not scanned: " + pidMaxPath + " is unreadable"}
	}
	var gaps []string
	hits := scanPIDs(ctx, limit, before)
	after, ok := procPIDs()
	if !ok {
		return nil, append(gaps, "process space unreadable after the scan: /proc could not be listed")
	}
	var hidden []int
	for _, pid := range hits {
		if before[pid] || after[pid] || isThread(pid) || !pidAlive(pid) {
			continue
		}
		hidden = append(hidden, pid)
	}
	sort.Ints(hidden)
	if len(hidden) > hiddenPIDShown {
		gaps = append(gaps, fmt.Sprintf("%d more hidden process(es) than the report shows", len(hidden)-hiddenPIDShown))
		hidden = hidden[:hiddenPIDShown]
	}
	return hidden, gaps
}

// pidCeiling is the highest pid the namespace may have allocated. ns_last_pid
// is the kernel's own last allocation; when it sits above every visible pid,
// the allocation sequence has not wrapped and a hidden process cannot sit
// above it. A wrapped sequence (ns_last_pid below the highest visible pid) is
// indistinguishable from a reset, so the whole pid_max range is scanned. The
// file is root-only on some hosts; pid_max is the fallback.
func pidCeiling(known map[int]bool) int {
	limit := pidMax()
	if limit == 0 {
		return 0
	}
	visible := 0
	for pid := range known {
		if pid > visible {
			visible = pid
		}
	}
	data, err := os.ReadFile("/proc/sys/kernel/ns_last_pid")
	if err != nil {
		return limit
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || value <= 0 || value >= limit {
		return limit
	}
	if value > visible {
		return value + 1
	}
	return limit
}

// procHidePIDs reads the /proc mount's hidepid option. Any non-zero value
// hides other accounts' processes from the directory listing, which would
// make an ordinary process look hidden.
func procHidePIDs() int {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[4] != "/proc" {
			continue
		}
		for _, option := range strings.Split(fields[5], ",") {
			value, ok := strings.CutPrefix(option, "hidepid=")
			if !ok {
				continue
			}
			hidepid, _ := strconv.Atoi(value)
			return hidepid
		}
	}
	return 0
}

// isThread reports whether pid is a non-leader thread. Threads answer kill(0)
// but have no top-level /proc directory entry; without this check every
// thread would read as a hidden process.
func isThread(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false
	}
	tgid, self := 0, 0
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "Tgid:"); ok {
			tgid, _ = strconv.Atoi(strings.TrimSpace(value))
		}
		if value, ok := strings.CutPrefix(line, "Pid:"); ok {
			self, _ = strconv.Atoi(strings.TrimSpace(value))
		}
	}
	return tgid > 0 && self > 0 && tgid != self
}

// procPIDs lists the numeric entries of /proc.
func procPIDs() (map[int]bool, bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, false
	}
	pids := make(map[int]bool, len(entries))
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err == nil {
			pids[pid] = true
		}
	}
	return pids, true
}

// scanPIDs asks kill(0) about every pid the kernel could have handed out. A
// hidden process still answers; a live one that started after the first
// listing is filtered by the second listing in readHiddenPIDs. The scan is
// chunked across workers because 4 million questions is the normal pid_max.
func scanPIDs(ctx context.Context, limit int, known map[int]bool) []int {
	workers := runtimeWorkers()
	chunk := (limit + workers - 1) / workers
	var (
		mu        sync.Mutex
		hits      []int
		workersWG sync.WaitGroup
	)
	for worker := 0; worker < workers; worker++ {
		start := worker * chunk
		end := min(start+chunk, limit)
		if start >= end {
			break
		}
		workersWG.Add(1)
		go func(start, end int) {
			defer workersWG.Done()
			var local []int
			for pid := start; pid < end; pid++ {
				if pid < 2 || known[pid] {
					continue
				}
				if pid%4096 == 0 && ctx.Err() != nil {
					break
				}
				if pidAlive(pid) {
					local = append(local, pid)
				}
			}
			if len(local) > 0 {
				mu.Lock()
				hits = append(hits, local...)
				mu.Unlock()
			}
		}(start, end)
	}
	workersWG.Wait()
	return hits
}

// runtimeWorkers bounds the brute-force scan without oversubscribing a small
// host or leaving a large one single-threaded.
func runtimeWorkers() int {
	return min(max(runtime.GOMAXPROCS(0)*8, 8), 32)
}

// collectLoader reads ld.so.conf, its includes and the directories they name.
// The configuration files are TCB objects; every search directory is checked
// for a non-root owner or group/other write, and every unowned .so inside one
// is a candidate for a soname replacement.
func collectLoader(ctx context.Context, state *KernelState, snapshot *Snapshot, facts func(string) trust.Facts, prefetch func([]string)) []string {
	var gaps []string
	visited := map[string]bool{}
	var dirs []string
	seenDir := map[string]bool{}

	var walk func(path string, depth int)
	walk = func(path string, depth int) {
		if depth > 4 || visited[path] {
			return
		}
		data, err := readCapped(path, configTextLimit)
		if err != nil {
			return
		}
		visited[path] = true
		state.LoaderConfig = append(state.LoaderConfig, path)
		remember(snapshot, path, facts(path))
		if quote, ok := sourceQuote(path, data); ok {
			quoteInto(state, path, quote)
		}
		includes, parsedDirs := parseLdSoConf(string(data))
		for _, pattern := range includes {
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join("/etc", pattern)
			}
			matches, _ := filepath.Glob(pattern)
			sort.Strings(matches)
			for _, match := range matches {
				walk(match, depth+1)
			}
		}
		for _, dir := range parsedDirs {
			if !seenDir[dir] {
				seenDir[dir] = true
				dirs = append(dirs, dir)
			}
		}
	}

	walk("/etc/ld.so.conf", 0)
	matches, _ := filepath.Glob("/etc/ld.so.conf.d/*.conf")
	sort.Strings(matches)
	for _, match := range matches {
		walk(match, 0)
	}
	sort.Strings(dirs)
	prefetch(dirs)
	for _, dir := range dirs {
		dirFacts := facts(dir)
		if dirFacts.Kind != trust.Dir {
			continue
		}
		state.LoaderDirs = append(state.LoaderDirs, LoaderDir{Path: dir, Facts: dirFacts})
	}

	var candidates []string
	seenFile := map[string]bool{}
	truncated := false
	for _, dir := range state.LoaderDirs {
		entries, err := os.ReadDir(dir.Path)
		if err != nil {
			gaps = append(gaps, "dynamic loader search directory is unreadable: "+dir.Path)
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !strings.Contains(name, ".so") {
				continue
			}
			if len(candidates) >= loaderScanLimit {
				truncated = true
				break
			}
			path := filepath.Join(dir.Path, name)
			if seenFile[path] {
				continue
			}
			seenFile[path] = true
			candidates = append(candidates, path)
		}
		if truncated {
			break
		}
	}
	if truncated {
		gaps = append(gaps, fmt.Sprintf("loader search scan stopped at %d files", loaderScanLimit))
	}
	catalog := snapshot.catalog
	if catalog == nil || catalog.Kind() == "none" {
		gaps = append(gaps, "loader search ownership unavailable: no package database")
		return gaps
	}
	for _, path := range candidates {
		fileFacts := facts(path)
		if fileFacts.Kind != trust.File || catalog.OwnedPath(path) || catalog.OwnedPath(fileFacts.Real) {
			// A soname is commonly a symlink into a multiarch subdirectory or
			// an alternatives target; the package list records the resolved
			// file, so the resolved spelling answers too.
			continue
		}
		state.LoaderFiles = append(state.LoaderFiles, LoaderFile{Path: path, Facts: fileFacts})
	}
	sort.Slice(state.LoaderFiles, func(i, j int) bool { return state.LoaderFiles[i].Path < state.LoaderFiles[j].Path })
	gaps = append(gaps, "loader search compared "+catalog.Kind()+" package file lists")
	return gaps
}

// parseLdSoConf reads one dynamic loader configuration file: include globs
// and the search directories it names. `hwcap` rows are glibc's capability
// annotations, not directories.
func parseLdSoConf(text string) (includes, dirs []string) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if cut := strings.IndexByte(line, '#'); cut >= 0 {
			line = strings.TrimSpace(line[:cut])
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		switch fields[0] {
		case "include":
			if len(fields) >= 2 {
				includes = append(includes, fields[1])
			}
		case "hwcap":
			continue
		default:
			dir := fields[0]
			if !filepath.IsAbs(dir) {
				dir = filepath.Join("/etc", dir)
			}
			dirs = append(dirs, filepath.Clean(dir))
		}
	}
	return includes, dirs
}

// collectDormantModules reads the out-of-tree drop points: module root files,
// updates/dkms, extra, weak-updates and misc. A .ko that is not loaded is
// still a future execution; the graph keeps it as a dormant module node.
func collectDormantModules(snapshot *Snapshot, state *KernelState, facts func(string) trust.Facts, prefetch func([]string)) []string {
	release := snapshot.Host.Kernel
	if release == "" {
		return nil
	}
	root := filepath.Join("/lib/modules", release)
	if _, err := os.Stat(root); err != nil {
		return nil
	}
	loaded := map[string]bool{}
	for _, module := range state.Modules {
		if module.File != "" {
			loaded[module.File] = true
		}
	}
	var candidates []string
	addFile := func(path string, info os.FileInfo) {
		if info == nil || !info.Mode().IsRegular() || moduleName(info.Name()) == "" {
			return
		}
		if loaded[path] {
			return
		}
		candidates = append(candidates, path)
	}
	if entries, err := os.ReadDir(root); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			info, err := entry.Info()
			if err == nil {
				addFile(filepath.Join(root, entry.Name()), info)
			}
		}
	}
	for _, dir := range []string{"updates", "updates/dkms", "extra", "weak-updates", "misc"} {
		base := filepath.Join(root, dir)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		count := 0
		_ = filepath.WalkDir(base, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() || count > 5000 {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return nil
			}
			if info.Mode().IsRegular() {
				count++
				addFile(path, info)
			}
			return nil
		})
	}
	if len(candidates) == 0 {
		return nil
	}
	prefetch(candidates)
	for _, path := range candidates {
		module := KernelModule{
			Name: moduleName(filepath.Base(path)), File: path,
			FileState: ModuleFileDormant, Facts: facts(path),
		}
		state.Dormant = append(state.Dormant, module)
		remember(snapshot, path, module.Facts)
	}
	sort.Slice(state.Dormant, func(i, j int) bool { return state.Dormant[i].File < state.Dormant[j].File })
	return nil
}

// judgeKernel adds the kernel domain's findings. KernelModule files are judged as
// artifacts; hidden modules, hidden pids and forced taint have no file and
// are stated as kernel state. The global findings stay out of a path, pid or
// unit scope.
func judgeKernel(snapshot *Snapshot, a *assessor, filter Filter, add func(Finding)) []string {
	state := &snapshot.Kernel
	if !state.Collected || len(filter.PIDs) > 0 || len(filter.Units) > 0 {
		return nil
	}
	var coverage []string
	unmapped := 0
	for _, module := range state.Modules {
		if module.FileState == ModuleFileUnmapped {
			unmapped++
		}
	}
	shownUnmapped := 0
	for _, module := range state.Modules {
		if module.FileState == ModuleFileUnmapped {
			if state.MappingStale || shownUnmapped >= registryGapShown {
				continue
			}
			shownUnmapped++
		}
		judgeModule(module, a, filter, add)
	}
	if !state.MappingStale && unmapped > registryGapShown {
		coverage = append(coverage, fmt.Sprintf("%d more unmapped module(s) than the report shows", unmapped-registryGapShown))
	}
	for _, module := range state.Dormant {
		judgeModule(module, a, filter, add)
	}
	for _, name := range state.RegistryGaps {
		if !globalScope(filter) {
			continue
		}
		add(Finding{
			Class: "module-registry-gap", Severity: Medium,
			Title: "module list carries a module the kernel did not register in sysfs",
			Path:  procModulesPath, Origin: Unknown, Reach: KernelAsset,
			Detail: fmt.Sprintf("module %s has no /sys/module/%s/sections entry", name, name),
			Evidence: []string{
				"the module is present in both /proc/modules reads",
				"/sys/module/" + name + "/sections is missing",
			},
		})
	}
	if globalScope(filter) {
		for _, hidden := range state.Hidden {
			add(Finding{
				Class: "hidden-module", Severity: Critical,
				Title: "kernel module hidden from /proc/modules",
				Path:  hiddenPath(hidden), Origin: Unknown, Reach: KernelAsset,
				Detail: fmt.Sprintf("module %s is carried by %s while the module list does not name it",
					hidden.Name, strings.Join(hidden.Views, " and ")),
				Evidence: []string{
					"module " + hidden.Name + " appears in " + strings.Join(hidden.Views, ", "),
					"/proc/modules did not name it in either read",
				},
			})
		}
		if finding, ok := taintFinding(state); ok {
			add(finding)
		}
		for _, pid := range state.HiddenPIDs {
			add(Finding{
				Class: "hidden-process", Severity: Critical,
				Title: "process hidden from /proc",
				Path:  fmt.Sprintf("/proc/%d", pid), Origin: Unknown, Reach: KernelAsset,
				Detail: fmt.Sprintf("pid %d is alive to the kernel and absent from /proc", pid),
				Evidence: []string{
					fmt.Sprintf("kill(%d, 0) reports the process exists", pid),
					fmt.Sprintf("/proc/%d was absent from both directory listings", pid),
				},
			})
		}
	}

	for _, dir := range state.LoaderDirs {
		if !pathOrRealInScope(dir.Path, dir.Facts.Real, filter) {
			continue
		}
		story := a.read(dir.Facts, false)
		evidence := []string{
			fmt.Sprintf("search directory %s: owner %d, mode %s", dir.Path, dir.Facts.Owner, dir.Facts.Mode.Perm()),
			fmt.Sprintf("origin %s (%s)", story.origin, story.why),
		}
		evidence = append(evidence, story.evidence...)
		if dir.Facts.Owner != 0 || dir.Facts.Writable {
			add(Finding{
				Class: "loader-path-writable", Severity: High,
				Title: "dynamic loader search directory writable by someone other than root",
				Path:  dir.Path, Origin: story.origin, Reach: RootAsset,
				Detail:   "a writer can replace a library every root process loads",
				Evidence: evidence,
			})
		}
	}

	var unowned []LoaderFile
	for _, file := range state.LoaderFiles {
		if pathOrRealInScope(file.Path, file.Facts.Real, filter) {
			unowned = append(unowned, file)
		}
	}
	if len(unowned) > loaderFileShown {
		coverage = append(coverage, fmt.Sprintf("%d more unowned loader file(s) than the report shows", len(unowned)-loaderFileShown))
		unowned = unowned[:loaderFileShown]
	}
	for _, file := range unowned {
		story := a.read(file.Facts, false)
		severity := Medium
		if story.origin == Runtime || story.origin == Modified {
			severity = severityFor(story.origin, RootAsset)
		}
		evidence := []string{
			fmt.Sprintf("search path %s is read by every dynamic execution", filepath.Dir(file.Path)),
			fmt.Sprintf("origin %s (%s)", story.origin, story.why),
		}
		evidence = append(evidence, story.evidence...)
		add(Finding{
			Class: "loader-path-unowned", Severity: severity,
			Title: "shared library in a loader search path no package owns",
			Path:  file.Path, Origin: story.origin, Reach: RootAsset,
			Detail:   "an unowned library in a search directory can stand in for a package's soname",
			Evidence: evidence,
		})
	}

	for _, path := range state.LoaderConfig {
		facts := snapshot.Facts(path)
		if !pathOrRealInScope(path, facts.Real, filter) {
			continue
		}
		story := a.read(facts, true)
		evidence := []string{
			fmt.Sprintf("dynamic loader configuration %s: %s (%s)", path, story.origin, story.why),
			fmt.Sprintf("owner %d, mode %s", facts.Owner, facts.Mode.Perm()),
		}
		evidence = append(evidence, story.evidence...)
		quotes := kernelQuotes(state, path)
		if story.origin == Runtime || story.origin == Modified {
			add(Finding{
				Class: "loader-config", Severity: severityFor(story.origin, RootAsset),
				Title: "dynamic loader search path changed after the artifact",
				Path:  path, Origin: story.origin, Reach: RootAsset,
				Detail: "every dynamic execution searches the directories this file names", Evidence: evidence,
				Quotes: quotes,
			})
		}
		if facts.Writable || facts.ParentOpen {
			add(Finding{
				Class: "loader-config-writable", Severity: writableSeverity(RootAsset),
				Title: "dynamic loader search path writable by someone other than its owner",
				Path:  path, Origin: story.origin, Reach: RootAsset,
				Detail: "a writer can add a directory every root process searches", Evidence: evidence,
				Quotes: quotes,
			})
		}
	}

	for _, path := range state.DeclarationFiles {
		facts := snapshot.Facts(path)
		if !pathOrRealInScope(path, facts.Real, filter) {
			continue
		}
		story := a.read(facts, true)
		evidence := []string{
			fmt.Sprintf("boot module list %s: %s (%s)", path, story.origin, story.why),
			fmt.Sprintf("owner %d, mode %s", facts.Owner, facts.Mode.Perm()),
		}
		evidence = append(evidence, story.evidence...)
		quotes := kernelQuotes(state, path)
		if story.origin == Runtime || story.origin == Modified {
			add(Finding{
				Class: "module-declaration", Severity: severityFor(story.origin, RootAsset),
				Title: "boot module list changed after the artifact",
				Path:  path, Origin: story.origin, Reach: RootAsset,
				Detail: "the modules named here load at boot with kernel authority", Evidence: evidence,
				Quotes: quotes,
			})
		}
		if facts.Writable || facts.ParentWritable {
			add(Finding{
				Class: "module-declaration-writable", Severity: writableSeverity(RootAsset),
				Title: "boot module list writable by someone other than its owner",
				Path:  path, Origin: story.origin, Reach: RootAsset,
				Detail: "a writer can choose a module the next boot loads as root", Evidence: evidence,
				Quotes: quotes,
			})
		}
	}
	return coverage
}

// judgeModule judges one loaded module's file. A module with no file to judge
// is still a module the kernel runs; the missing and unmapped states are the
// findings.
func judgeModule(module KernelModule, a *assessor, filter Filter, add func(Finding)) {
	if module.File != "" && !pathOrRealInScope(module.File, module.Facts.Real, filter) {
		return
	}
	evidence := moduleEvidence(module)
	if module.File != "" && module.Facts.Kind == trust.File && module.FileState != ModuleFileDormant {
		story := a.read(module.Facts, false)
		evidence = append(evidence,
			fmt.Sprintf("file %s: %s (%s)", module.File, story.origin, story.why))
		evidence = append(evidence, story.evidence...)
		switch {
		case story.origin == Runtime || story.origin == Modified:
			class := "module-introduction"
			title := "kernel module file introduced after the artifact"
			if story.origin == Modified {
				class, title = "module-modification", "kernel module file changed after the artifact"
			}
			add(Finding{
				Class: class, Severity: severityFor(story.origin, KernelAsset),
				Title: title, Path: module.File, Origin: story.origin, Reach: KernelAsset,
				Detail:   fmt.Sprintf("module %s is loaded and its file is outside the artifact", module.Name),
				Evidence: evidence,
			})
			return
		case module.Facts.Writable || module.Facts.ParentOpen:
			add(Finding{
				Class: "module-writable", Severity: writableSeverity(KernelAsset),
				Title: "kernel module file writable by someone other than its owner",
				Path:  module.File, Origin: story.origin, Reach: KernelAsset,
				Detail: "a writer can replace the code the kernel runs", Evidence: evidence,
			})
			return
		case module.Facts.PackageKnown && module.Facts.Package == "":
			add(Finding{
				Class: "module-unowned", Severity: High,
				Title: "loaded kernel module's file no package owns",
				Path:  module.File, Origin: story.origin, Reach: KernelAsset,
				Detail: "the module runs in the kernel and has no distribution owner", Evidence: evidence,
			})
			return
		}
		return
	}
	switch module.FileState {
	case ModuleFileMissing:
		add(Finding{
			Class: "module-file-missing", Severity: High,
			Title: "loaded kernel module's file is missing from disk",
			Path:  module.File, Origin: Unknown, Reach: KernelAsset,
			Detail:   fmt.Sprintf("module %s is loaded; modules.dep names a file the disk does not carry", module.Name),
			Evidence: evidence,
		})
	case ModuleFileUnmapped:
		if !globalScope(filter) {
			return
		}
		add(Finding{
			Class: "module-unmapped", Severity: High,
			Title: "loaded kernel module not named by modules.dep",
			Path:  procModulesPath, Origin: Unknown, Reach: KernelAsset,
			Detail:   fmt.Sprintf("module %s is loaded and the module database names no file for it", module.Name),
			Evidence: evidence,
		})
	case ModuleFileDormant:
		if !globalScope(filter) {
			return
		}
		story := a.read(module.Facts, false)
		severity := Medium
		detail := "a dormant module file is a future kernel execution"
		switch {
		case story.origin == Runtime || story.origin == Modified:
			severity = severityFor(story.origin, KernelAsset)
			detail = "the module file was introduced or changed after the artifact"
		case module.Facts.PackageKnown && module.Facts.Package == "":
			severity = High
			detail = "the module file has no package owner and is not loaded"
			if strings.Contains(module.File, "/updates/dkms/") {
				// DKMS builds are legitimately unowned; the build path is the
				// context that keeps this a lead rather than a verdict.
				severity = Medium
				detail = "an unowned DKMS-built module; verify the DKMS registration"
			}
		case module.Facts.Writable || module.Facts.ParentOpen:
			severity = High
			detail = "a writer can change a module the next boot can load"
		default:
			return
		}
		add(Finding{
			Class: "module-dormant", Severity: severity,
			Title: "out-of-tree kernel module file outside package management",
			Path:  module.File, Origin: story.origin, Reach: KernelAsset,
			Detail: detail, Evidence: evidence,
			Trace: steps("module file "+module.File, story.origin.String(), "not loaded"),
		})
	}
}

// moduleEvidence is the registry side of one module: its flags, which views
// carry it, and the declarations that ask for it.
func moduleEvidence(module KernelModule) []string {
	lines := []string{fmt.Sprintf("module %s state %s, used by %d", module.Name, module.State, module.Used)}
	if module.Taint != "" {
		lines = append(lines, "module loader flags "+module.Taint)
	}
	var views []string
	if module.InSysfs {
		views = append(views, "sysfs")
	}
	if module.InKallsyms {
		views = append(views, "kallsyms")
	}
	if len(views) > 0 {
		lines = append(lines, "carried by "+strings.Join(views, ", "))
	}
	lines = append(lines, module.Declared...)
	return lines
}

// hiddenPath is where the operator can read the module's surviving registry
// entry.
func hiddenPath(hidden HiddenModule) string {
	for _, view := range hidden.Views {
		if view == "sysfs" {
			return filepath.Join(sysModuleDir, hidden.Name)
		}
	}
	return kallsymsPath
}

// taintFinding states the taint bits that record an operation rather than a
// stock out-of-tree module. Those bits name forced load/unload and a bad page;
// out-of-tree and unsigned are already visible on each module row.
func taintFinding(state *KernelState) (Finding, bool) {
	var flagged []string
	severity := Medium
	for bit, name := range taintTable {
		if state.Tainted&(1<<bit) == 0 {
			continue
		}
		switch bit {
		case 1, 3:
			flagged = append(flagged, name)
			severity = High
		case 5:
			flagged = append(flagged, name)
		}
	}
	if len(flagged) == 0 {
		return Finding{}, false
	}
	return Finding{
		Class: "kernel-taint", Severity: severity,
		Title: "kernel taint records a forced module operation",
		Path:  taintedPath, Origin: Unknown, Reach: KernelAsset,
		Detail: fmt.Sprintf("taint mask %d: %s", state.Tainted, strings.Join(flagged, ", ")),
		Evidence: []string{
			fmt.Sprintf("kernel taint mask %d", state.Tainted),
			strings.Join(state.TaintNames, ", "),
		},
	}, true
}

// globalScope reports whether a finding about the host itself belongs in this
// run. A path, pid or unit scope asks about one object; a clock skew or a
// hidden module has no path to match.
func globalScope(filter Filter) bool {
	return len(filter.Paths) == 0 && len(filter.PIDs) == 0 && len(filter.Units) == 0
}

// pathOrRealInScope answers a path scope under either spelling: the package
// database and /lib -> /usr/lib disagree on where a module file lives.
func pathOrRealInScope(path, real string, filter Filter) bool {
	if pathInScope(path, filter) {
		return true
	}
	return real != "" && real != path && pathInScope(real, filter)
}
