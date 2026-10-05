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
	"strconv"
	"strings"

	"karma/internal/model"
)

// ModulesLoad mirrors the check's modulesLoadScript: the /etc/modules file and
// the load layers it hands in, one section each.
func ModulesLoad(paths []string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return ReadSections(paths, nil), nil }
}

// ModulesHidden mirrors hiddenModuleScript: every loadable module has a
// sections/ directory under /sys/module; one that /proc/modules does not list
// is hidden from the module registry.
func ModulesHidden(ctx context.Context) (string, error) {
	entries, err := os.ReadDir("/sys/module")
	if err != nil {
		return "", model.ErrTierUnavailable
	}
	body, err := os.ReadFile("/proc/modules")
	if err != nil {
		return "", model.ErrTierUnavailable
	}
	loaded := map[string]bool{}
	for _, line := range strings.Split(string(body), "\n") {
		name, _, _ := strings.Cut(line, " ")
		if name != "" {
			loaded[name] = true
		}
	}
	var b strings.Builder
	for _, entry := range entries {
		if info, err := os.Stat(filepath.Join("/sys/module", entry.Name(), "sections")); err == nil &&
			info.IsDir() && !loaded[entry.Name()] {
			fmt.Fprintf(&b, "HIDDEN %s\n", entry.Name())
		}
	}
	return b.String(), nil
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
	if release, ok := kernelRelease(); ok {
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
