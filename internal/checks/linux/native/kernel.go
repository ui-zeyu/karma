// native tiers of the kernel checks: boot module lists, the hidden-module
// cross-check, the module-memory diff, kallsyms signatures and taint flags.

package native

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"karma/internal/localfs"
	"karma/internal/model"
	"karma/internal/script"
)

// ModulesLoad mirrors the check's modulesLoadScript: the /etc/modules file and
// the load layers it hands in, one section each.
func ModulesLoad(paths []string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return localfs.ReadSections(paths, nil), nil }
}

// ModuleAttr is one sysfs attribute a hidden module's evidence line carries: the
// label the line prints and the attribute's name under /sys/module/<module>/.
type ModuleAttr struct {
	Label string
	File  string
}

// PseudoModuleTags are the module tags in /proc/kallsyms that are not modules:
// JITed BPF programs carry [bpf], and the pages the kernel allocates for ftrace
// and kprobes trampolines carry [__builtin__ftrace] and [__builtin__kprobes]
// (kernel/kallsyms.c names them itself, so a stack trace can tell those pages
// from a module's). The loader registered none of them, so /proc/modules never
// lists them and the cross-check would report a hidden module that does not
// exist — as a Critical finding — on every host with such trampolines.
var PseudoModuleTags = []string{"bpf", "__builtin__ftrace", "__builtin__kprobes"}

// The three kernel surfaces the hidden-module diff reads, and the core file the
// module-memory dig reads behind its rows.
const (
	sysModuleRoot    = "/sys/module"
	procModulesFile  = "/proc/modules"
	procKallsymsFile = "/proc/kallsyms"
	procKcoreFile    = "/proc/kcore"
)

// ModuleDiffViews is the one value both channels of the hidden-module diff
// read: the surfaces, the attributes a module's evidence line carries, and the
// symbol tags that are not modules. The check hands it to the in-process body
// and to the pipeline, so the two cannot read different paths or attribute
// lists.
func ModuleDiffViews(attrs []ModuleAttr) script.ModuleDiffViews {
	pairs := make([]string, 0, len(attrs))
	for _, attr := range attrs {
		pairs = append(pairs, attr.Label+":"+attr.File)
	}
	return script.ModuleDiffViews{
		SysfsRoot:   sysModuleRoot,
		ModulesPath: procModulesFile,
		SymbolsPath: procKallsymsFile,
		Attrs:       pairs,
		PseudoTags:  PseudoModuleTags,
	}
}

// ModulesHidden is the merged diff body, mirroring script.HiddenModuleScript:
// the marked stream is built in process and joined by the same Go join the
// pipeline's awk mirrors. Either view can be unavailable on its own (no /sys
// mounted, no symbol table in a container); the module list is the baseline, so
// without it the tier reports itself unavailable and the channel falls through.
func ModulesHidden(views script.ModuleDiffViews) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		modules, err := os.ReadFile(views.ModulesPath)
		if err != nil {
			return "", model.ErrTierUnavailable
		}
		return script.HiddenModuleBody(hiddenModuleViewsText(views, string(modules))), nil
	}
}

// hiddenModuleViewsText is the in-process emitter of the marked stream
// HiddenModuleScript's shell block produces: the availability flags, one S line
// per loadable module with the attributes that read back, one P line per
// /proc/modules name, one K line per module tag in the symbol table.
func hiddenModuleViewsText(views script.ModuleDiffViews, modules string) string {
	var b strings.Builder
	sysfs, sysfsErr := os.ReadDir(views.SysfsRoot)
	fmt.Fprintf(&b, "A %s %d\n", viewSysfsName, boolBit(sysfsErr == nil))
	symbols, symbolsErr := os.ReadFile(views.SymbolsPath)
	fmt.Fprintf(&b, "A %s %d\n", viewKallsymsName, boolBit(symbolsErr == nil))

	if sysfsErr == nil {
		for _, entry := range sysfs {
			name := entry.Name()
			if info, err := os.Stat(filepath.Join(views.SysfsRoot, name, "sections")); err != nil || !info.IsDir() {
				continue
			}
			line := "S " + name
			dir := filepath.Join(views.SysfsRoot, name)
			for _, pair := range views.Attrs {
				label, file, _ := strings.Cut(pair, ":")
				if value, ok := readTrimmedFile(filepath.Join(dir, file)); ok {
					line += " " + label + " " + value
				}
			}
			b.WriteString(line + "\n")
		}
	}
	// The shell block prints /proc/modules' first column, so this emitter does
	// the same: a module list line carries the name, the size, the refcount and
	// the address, and only the name is a view of the registry.
	for _, name := range moduleListNames(modules) {
		b.WriteString("P " + name + "\n")
	}
	if symbolsErr == nil {
		for name, count := range symbolModuleNames(string(symbols)) {
			fmt.Fprintf(&b, "K %s %d\n", name, count)
		}
	}
	return b.String()
}

// viewSysfsName and viewKallsymsName are the view names script's body and awk
// program use in the availability flags and the row verdicts.
const (
	viewSysfsName    = "sysfs"
	viewKallsymsName = "kallsyms"
)

// boolBit renders an availability flag the way the shell block does.
func boolBit(ok bool) int {
	if ok {
		return 1
	}
	return 0
}

// moduleAllocators and sharedAllocators are the caller functions of the
// executable kernel memory /proc/vmallocinfo shows. move_module (the loader's
// own allocator, module_alloc on older kernels) is used by modules alone, while
// execmem_alloc (6.10 and later, which replaced both) is shared with JITed BPF
// programs and the kprobe and ftrace trampolines — measured on a stock 7.0
// desktop, 132 execmem_alloc regions against 50 modules.
var (
	moduleAllocators = []string{"move_module", "module_alloc"}
	sharedAllocators = []string{"execmem_alloc"}
)

// ModuleMemoryViews is the one value both channels of the module-memory diff
// read.
func ModuleMemoryViews() script.ModuleMemoryViews {
	return script.ModuleMemoryViews{
		VMallocPath:      "/proc/vmallocinfo",
		ModulesPath:      procModulesFile,
		SymbolsPath:      procKallsymsFile,
		ModuleAllocators: moduleAllocators,
		SharedAllocators: sharedAllocators,
		PseudoTags:       PseudoModuleTags,
		CorePath:         procKcoreFile,
	}
}

// ModuleMemory is the local tier of the module-memory diff, mirroring
// script.ModuleMemoryScript: the three surfaces are read in process, the marked
// stream is built the way the shell block builds it, and the same Go join
// renders the rows the pipeline's awk mirrors. The symbol table is required —
// without it every region would look unexplained — and so are the allocation
// list and the module list, which the shell block's `exit 1` mirrors.
//
// The rows that join could not explain are then read out of the running kernel's
// core file (ModuleImages), which is this channel's own step: a remote shell has
// no way to read the core, so the pipeline's rows stand alone there. The read is
// bounded and silent when it cannot happen or finds nothing, so a host without a
// readable core answers exactly the rows the pipeline prints.
func ModuleMemory(views script.ModuleMemoryViews, kitNames *regexp.Regexp) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		allocations, err := os.ReadFile(views.VMallocPath)
		if err != nil {
			return "", model.ErrTierUnavailable
		}
		modules, err := os.ReadFile(views.ModulesPath)
		if err != nil {
			return "", model.ErrTierUnavailable
		}
		symbols, err := os.ReadFile(views.SymbolsPath)
		if err != nil {
			return "", model.ErrTierUnavailable
		}
		stream := moduleMemoryText(views, string(allocations), string(modules), string(symbols))
		rows, unowned := script.ModuleMemoryRows(views, stream)
		if images := ModuleImages(views.CorePath, unowned, kitNames); len(images) > 0 {
			// The dig's rows belong with the memory they name: after the rows
			// nothing explains, and before the accounting line that closes the
			// report.
			rows = slices.Insert(rows, len(rows)-1, images...)
		}
		return strings.Join(rows, "\n") + "\n", nil
	}
}

// moduleMemoryRegion is one allocation the kernel's own allocators made.
type moduleMemoryRegion struct {
	index int
	start uint64
	end   uint64
	size  string
	class string
}

// moduleMemoryText is the in-process emitter of the marked stream
// ModuleMemoryScript's shell block produces: one R line per allocation, one P
// line per module-list name, one Y line per symbol inside an allocation.
func moduleMemoryText(views script.ModuleMemoryViews, allocations, modules, symbols string) string {
	classes := map[string]string{}
	for _, name := range views.ModuleAllocators {
		classes[name] = "module"
	}
	for _, name := range views.SharedAllocators {
		classes[name] = "shared"
	}
	var (
		regions []moduleMemoryRegion
		b       strings.Builder
	)
	for line := range strings.SplitSeq(allocations, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		start, end, ok := splitAddressRange(fields[0])
		if !ok {
			continue
		}
		caller, _, _ := strings.Cut(fields[2], "+")
		class, known := classes[caller]
		if !known {
			continue
		}
		index := len(regions) + 1
		regions = append(regions, moduleMemoryRegion{index: index, start: start, end: end, size: fields[1], class: class})
		startText, endText, _ := strings.Cut(fields[0], "-")
		fmt.Fprintf(&b, "R %d %s %s %s %s\n", index, startText, endText, fields[1], class)
	}
	for _, name := range moduleListNames(modules) {
		b.WriteString("P " + name + "\n")
	}
	sorted := slices.Clone(regions)
	slices.SortFunc(sorted, func(a, b moduleMemoryRegion) int { return cmp.Compare(a.start, b.start) })
	for line := range strings.SplitSeq(symbols, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		address, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil {
			continue
		}
		index, found := slices.BinarySearchFunc(sorted, address, func(r moduleMemoryRegion, a uint64) int {
			switch {
			case a < r.start:
				return 1
			case a >= r.end:
				return -1
			default:
				return 0
			}
		})
		if !found {
			continue
		}
		tag := "-"
		if strings.HasSuffix(line, "]") {
			if open := strings.LastIndexByte(line, '['); open >= 0 {
				tag = line[open+1 : len(line)-1]
			}
		}
		fmt.Fprintf(&b, "Y %d %s\n", sorted[index].index, tag)
	}
	return b.String()
}

// splitAddressRange splits vmallocinfo's "0xstart-0xend" first field.
func splitAddressRange(field string) (uint64, uint64, bool) {
	start, end, ok := strings.Cut(field, "-")
	if !ok {
		return 0, 0, false
	}
	lo, err := strconv.ParseUint(strings.TrimPrefix(start, "0x"), 16, 64)
	if err != nil {
		return 0, 0, false
	}
	hi, err := strconv.ParseUint(strings.TrimPrefix(end, "0x"), 16, 64)
	if err != nil {
		return 0, 0, false
	}
	return lo, hi, true
}

// moduleListNames is /proc/modules' first column, in the order the file lists
// the modules: a line carries the name, the size, the refcount, the dependent
// list, the state and the address, and only the name is a view of the registry.
func moduleListNames(body string) []string {
	var names []string
	for line := range strings.SplitSeq(body, "\n") {
		if name, _, _ := strings.Cut(line, " "); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// symbolModuleNames counts the module tags in a /proc/kallsyms body. A tagged
// line ends with the module in brackets after a tab
// ("__kstrtab_nft_do_chain\t[nf_tables]"); an untagged line is a kernel symbol.
// The pseudo-module tags in PseudoModuleTags are left out, so the difference
// against /proc/modules stays a hidden-module signal.
func symbolModuleNames(body string) map[string]int {
	counts := map[string]int{}
	for line := range strings.SplitSeq(body, "\n") {
		if !strings.HasSuffix(line, "]") {
			continue
		}
		start := strings.LastIndexByte(line, '[')
		if start < 0 {
			continue
		}
		name := line[start+1 : len(line)-1]
		if name == "" || slices.Contains(PseudoModuleTags, name) {
			continue
		}
		counts[name]++
	}
	return counts
}

// readTrimmedFile reads one sysfs attribute, trimmed; an unreadable or empty
// attribute reports false so the evidence line skips it.
func readTrimmedFile(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	value := strings.TrimSpace(string(data))
	return value, value != ""
}

// Kallsyms mirrors the check's kallsymsScript: the symbol table narrowed to
// the families the check hands in, in process; no hit stays empty and quiet.
func Kallsyms(pattern *regexp.Regexp) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		data, err := os.ReadFile("/proc/kallsyms")
		if err != nil {
			return "", model.ErrTierUnavailable
		}
		return filteredLines(string(data), pattern.MatchString), nil
	}
}

// ProcModules reads the module registry the cat tier reads.
func ProcModules(ctx context.Context) (string, error) {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return "", model.ErrTierUnavailable
	}
	return string(data), nil
}

// stripSyslogPriority drops the "<N>" facility/level prefix the kernel stores
// at the head of every ring-buffer line: dmesg parses it and prints the line
// without it, and that is the text the rules read. A line whose angle brackets
// do not hold a number stays untouched.
func stripSyslogPriority(body string) string {
	if !strings.Contains(body, "<") {
		return body
	}
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		if end := strings.IndexByte(line, '>'); end > 1 && end <= 4 && strings.HasPrefix(line, "<") {
			if _, err := strconv.Atoi(line[1:end]); err == nil {
				lines[i] = line[end+1:]
			}
		}
	}
	return strings.Join(lines, "\n")
}

// Lsmod formats /proc/modules as the lsmod table — header included, so
// the lsmod lexer reads both channels' output the same way.
func Lsmod(ctx context.Context) (string, error) {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return "", model.ErrTierUnavailable
	}
	return lsmodRows(string(data)), nil
}

// lsmodRows renders /proc/modules in lsmod's own layout: a 19-cell module
// name, the size in eight, two blanks, then the use count, and the dependent
// list after one blank only when the module has dependents (lsmod leaves no
// trailing blank, and the fourth field is "-" when there are none).
//
// The kernel's dependent field is a comma-terminated list ("udp_diag,tcp_diag,"),
// while lsmod joins the names with commas and no terminator; the trailing comma
// is dropped here. The names themselves come in the kernel's own order, which
// can differ from the sysfs holder order lsmod reads its column from — the set
// is the same either way.
func lsmodRows(data string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-19s %8s  %s\n", "Module", "Size", "Used by")
	for line := range strings.SplitSeq(data, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		fmt.Fprintf(&b, "%-19s %8s  %s", f[0], f[1], f[2])
		if len(f) >= 4 {
			if dependents := strings.TrimSuffix(f[3], ","); dependents != "-" {
				b.WriteString(" " + dependents)
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// Tainted reads the taint mask. procfs.KernelTainted covers the same file
// but is Linux-only, and this tier is defined on every platform (it reports
// itself unavailable where /proc is absent); the file holds one integer, so it
// is read directly.
func Tainted(ctx context.Context) (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/tainted")
	if err != nil {
		return "", model.ErrTierUnavailable
	}
	return string(data), nil
}
