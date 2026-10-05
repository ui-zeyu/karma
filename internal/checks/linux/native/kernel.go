// native tiers of the kernel checks: boot module lists, the hidden-module
// cross-check, kallsyms signatures, taint flags, and signature config.

package native

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"karma/internal/localfs"
	"karma/internal/model"
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

// bpfModuleTag is the pseudo-module kallsyms tags JITed BPF programs with. Those
// programs are not modules and /proc/modules never lists them, so the tag is
// dropped from the symbol-table cross-check.
const bpfModuleTag = "bpf"

// The three kernel surfaces the hidden-module cross-check diffs.
const (
	sysModuleRoot    = "/sys/module"
	procModulesFile  = "/proc/modules"
	procKallsymsFile = "/proc/kallsyms"
)

// ModulesHidden is the merged cross-check body, mirroring hiddenModuleScript:
// the sysfs diff and the kallsyms diff in one tier, so both footprints land in
// the same panel. Either half can be unavailable on its own (no /sys mounted, no
// symbol table in a container); the tier reports unavailable only when both are,
// so one half's absence does not drop the other's evidence.
func ModulesHidden(attrs []ModuleAttr) func(context.Context) (string, error) {
	return hiddenModulesBody(attrs, sysModuleRoot, procModulesFile, procKallsymsFile)
}

// hiddenModulesBody is that tier over given surfaces, the ones the tests
// substitute a fixture for.
func hiddenModulesBody(attrs []ModuleAttr, sysfsRoot, modulesPath, symbolsPath string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var b strings.Builder
		available := false
		for _, half := range []func(context.Context) (string, error){
			hiddenModulesFromSysfs(attrs, sysfsRoot, modulesPath),
			hiddenModulesFromSymbols(modulesPath, symbolsPath),
		} {
			text, err := half(ctx)
			if err != nil {
				continue
			}
			available = true
			b.WriteString(text)
		}
		if !available {
			return "", model.ErrTierUnavailable
		}
		return b.String(), nil
	}
}

// hiddenModulesFromSysfs is the sysfs half: every loadable module has a
// sections/ directory under /sys/module; one that /proc/modules does not list is
// hidden from the module registry. The evidence line carries the attributes the
// check hands in, so the module the loader created stays identifiable by size,
// code address, refcount, state and taint letters even though the list has
// forgotten it.
func hiddenModulesFromSysfs(attrs []ModuleAttr, sysfsRoot, modulesPath string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		entries, err := os.ReadDir(sysfsRoot)
		if err != nil {
			return "", model.ErrTierUnavailable
		}
		body, err := os.ReadFile(modulesPath)
		if err != nil {
			return "", model.ErrTierUnavailable
		}
		loaded := loadedModuleNames(string(body))
		var b strings.Builder
		for _, entry := range entries {
			name := entry.Name()
			if loaded[name] {
				continue
			}
			if info, err := os.Stat(filepath.Join(sysfsRoot, name, "sections")); err != nil || !info.IsDir() {
				continue
			}
			dir := filepath.Join(sysfsRoot, name)
			fmt.Fprintf(&b, "%s\n", hiddenModuleLine(name, attrs, func(file string) (string, bool) {
				return readTrimmedFile(filepath.Join(dir, file))
			}))
		}
		return b.String(), nil
	}
}

// hiddenModulesFromSymbols is the kallsyms half of the same cross-check: the
// table prints the module a symbol came from in brackets after it, and that
// tag survives a module which scrubbed itself out of /proc/modules — a second,
// independent registry to diff the list against.
func hiddenModulesFromSymbols(modulesPath, symbolsPath string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		modules, err := os.ReadFile(modulesPath)
		if err != nil {
			return "", model.ErrTierUnavailable
		}
		symbols, err := os.ReadFile(symbolsPath)
		if err != nil {
			return "", model.ErrTierUnavailable
		}
		return hiddenModuleSymbolLines(symbolModuleNames(string(symbols)), loadedModuleNames(string(modules))), nil
	}
}

// loadedModuleNames is /proc/modules' first column as a set.
func loadedModuleNames(body string) map[string]bool {
	loaded := map[string]bool{}
	for _, line := range strings.Split(body, "\n") {
		name, _, _ := strings.Cut(line, " ")
		if name != "" {
			loaded[name] = true
		}
	}
	return loaded
}

// symbolModuleNames counts the module tags in a /proc/kallsyms body. A tagged
// line ends with the module in brackets after a tab
// ("__kstrtab_nft_do_chain\t[nf_tables]"); an untagged line is a kernel symbol.
// The [bpf] tag JITed BPF programs carry is not a module and is left out, so the
// difference against /proc/modules stays a hidden-module signal.
func symbolModuleNames(body string) map[string]int {
	counts := map[string]int{}
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasSuffix(line, "]") {
			continue
		}
		start := strings.LastIndexByte(line, '[')
		if start < 0 {
			continue
		}
		name := line[start+1 : len(line)-1]
		if name == "" || name == bpfModuleTag {
			continue
		}
		counts[name]++
	}
	return counts
}

// hiddenModuleSymbolLines renders one line per tagged module the loaded list does
// not carry, in name order: the HIDDEN marker the rule grades, the module name
// and how many of its symbols are still in the table.
func hiddenModuleSymbolLines(counts map[string]int, loaded map[string]bool) string {
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	slices.Sort(names)
	var b strings.Builder
	for _, name := range names {
		if loaded[name] {
			continue
		}
		fmt.Fprintf(&b, "HIDDEN %s symbols %d\n", name, counts[name])
	}
	return b.String()
}

// hiddenModuleLine is one sysfs evidence line: the HIDDEN marker the rule grades,
// the module's name, then every attribute that reads back non-empty. A missing
// or empty attribute (a module without taint letters, an unreadable .text) is
// left out rather than printed blank.
func hiddenModuleLine(name string, attrs []ModuleAttr, read func(file string) (string, bool)) string {
	var b strings.Builder
	b.WriteString("HIDDEN " + name)
	for _, attr := range attrs {
		if value, ok := read(attr.File); ok {
			b.WriteString(" " + attr.Label + " " + value)
		}
	}
	return b.String()
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
func lsmodRows(data string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-19s %8s  %s\n", "Module", "Size", "Used by")
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		fmt.Fprintf(&b, "%-19s %8s  %s", f[0], f[1], f[2])
		if len(f) >= 4 && f[3] != "-" {
			b.WriteString(" " + f[3])
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

// ModuleSig mirrors moduleSigScript: the ikconfig dump first, the
// /boot/config-<release> fallback second, both narrowed to CONFIG_MODULE_SIG;
// an empty answer stays silent on a custom kernel.
func ModuleSig(ctx context.Context) (string, error) {
	if body := configSigRows("/proc/config.gz", true); body != "" {
		return body, nil
	}
	if release, ok := localfs.KernelRelease(); ok {
		return configSigRows("/boot/config-"+release, false), nil
	}
	return "", nil
}

func configSigRows(path string, gzipped bool) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if gzipped {
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return ""
		}
		unpacked, err := io.ReadAll(reader)
		if err != nil {
			return ""
		}
		data = unpacked
	}
	return filteredLines(string(data), func(line string) bool {
		return strings.HasPrefix(line, "CONFIG_MODULE_SIG")
	})
}
