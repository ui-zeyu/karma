package audit

// Kernel module registries: the /proc, sysfs and kallsyms views, their three-way diff, the dependency mapping, the boot declarations and the dormant trees.

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"karma/internal/trust"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
)

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

func readKallsymsModules(ctx context.Context) (map[string]bool, bool, Coverage) {
	file, err := os.Open(kallsymsPath)
	if err != nil {
		return nil, false, Coverage{}
	}
	defer file.Close()
	modules := map[string]bool{}
	reader := bufio.NewReaderSize(file, 1<<20)
	var read int
	for {
		if err := ctx.Err(); err != nil {
			return modules, false, coverageAbsent("kernel", "kernel symbol table read stopped: "+err.Error())
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
			return modules, true, Coverage{}
		}
		if err != nil {
			return modules, false, coverageGap("kernel", "kernel symbol table unreadable: "+err.Error())
		}
		if read > kallsymsLimit {
			return modules, true, coverageGap("kernel", "kernel symbol table truncated at 64MiB; hidden-module cross-check is partial")
		}
	}
}

// diffModuleViews reports the names the registries disagree about. A name in
// sysfs or kallsyms that neither /proc/modules read carried is hidden; only a
// module both /proc reads carried is allowed to be a gap in sysfs.

func diffModuleViews(stable, loaded, sysfs map[string]bool, sysfsOK bool, symbols map[string]bool, kallsymsOK bool) ([]HiddenModule, []string, []Coverage) {
	var gaps []Coverage
	if sysfsOK && len(sysfs) == 0 && len(stable) > 0 {
		// Some container runtimes expose /sys without the module registry;
		// an empty view would turn every loaded module into a gap.
		gaps = append(gaps, coverageGap("kernel", "sysfs module registry is empty; the registry cross-check was skipped"))
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
		slices.Sort(seen)
		hidden = append(hidden, HiddenModule{Name: name, Views: seen})
	}
	sort.Slice(hidden, func(i, j int) bool { return hidden[i].Name < hidden[j].Name })
	var notes []Coverage
	hidden, notes = shownMore(hidden, hiddenModuleShown, "kernel", "hidden module(s)")
	gaps = append(gaps, notes...)
	var registryGaps []string
	if sysfsOK {
		for name := range stable {
			if !sysfs[name] {
				registryGaps = append(registryGaps, name)
			}
		}
		slices.Sort(registryGaps)
		var notes []Coverage
		registryGaps, notes = shownMore(registryGaps, registryGapShown, "kernel", "module registry gap(s)")
		gaps = append(gaps, notes...)
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

func readModuleDeclarations(snapshot *Snapshot, facts func(string) trust.Facts) (map[string][]string, []string, []Coverage) {
	if !snapshot.plan.Filter.touchesPath("/etc/modules") &&
		!snapshot.plan.Filter.touchesPath("/etc/modules-load.d") {
		return nil, nil, nil
	}
	var files []string
	declared := map[string][]string{}
	files = append(files, "/etc/modules")
	matches, _ := filepath.Glob("/etc/modules-load.d/*.conf")
	files = append(files, matches...)
	var paths []string
	var gaps []Coverage
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
		gaps = append(gaps, coverageAbsent("kernel", "no boot module declaration file was readable (/etc/modules, /etc/modules-load.d)"))
	}
	return declared, paths, gaps
}

// moduleDeclaration is one module named by a boot module list.

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

// dormantDropBudget bounds one drop tree's walk, so a staging tree cannot
// dominate the collection.
const dormantDropBudget = 5000

func collectDormantModules(snapshot *Snapshot, state *KernelState, facts func(string) trust.Facts) []Coverage {
	release := snapshot.Host.Kernel
	if release == "" {
		return nil
	}
	root := filepath.Join("/lib/modules", release)
	if !snapshot.plan.Filter.touchesPath(root) {
		return nil
	}
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
	var gaps []Coverage
	for _, dir := range []string{"updates", "updates/dkms", "extra", "weak-updates", "misc"} {
		base := filepath.Join(root, dir)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		count := 0
		stopped := false
		_ = filepath.WalkDir(base, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() {
				return nil
			}
			if count >= dormantDropBudget {
				stopped = true
				return filepath.SkipAll
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
		if stopped {
			gaps = append(gaps, coverageGap("kernel",
				"dormant module walk of "+base+" stopped at its file budget"))
		}
	}
	if len(candidates) == 0 {
		return gaps
	}
	for _, path := range candidates {
		module := KernelModule{
			Name: moduleName(filepath.Base(path)), File: path,
			FileState: ModuleFileDormant, Facts: facts(path),
		}
		state.Dormant = append(state.Dormant, module)
		remember(snapshot, path, module.Facts)
	}
	sort.Slice(state.Dormant, func(i, j int) bool { return state.Dormant[i].File < state.Dormant[j].File })
	return gaps
}
