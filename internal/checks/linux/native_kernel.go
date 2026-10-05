// native tiers of the kernel checks: boot module lists, the hidden-module
// cross-check, kallsyms signatures, taint flags, and signature config.

package linux

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"karma/internal/model"
)

// nativeModulesLoad mirrors modulesLoadScript: the /etc/modules file and the
// modules-load.d layers, one section each.
func nativeModulesLoad(ctx context.Context) (string, error) {
	return readSections([]string{
		"/etc/modules",
		"/etc/modules-load.d/*.conf",
		"/run/modules-load.d/*.conf",
		"/usr/local/lib/modules-load.d/*.conf",
	}, nil), nil
}

// nativeModulesHidden mirrors hiddenModuleScript: every loadable module has a
// sections/ directory under /sys/module; one that /proc/modules does not list
// is hidden from the module registry.
func nativeModulesHidden(ctx context.Context) (string, error) {
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

// kallsymsRe is the collection-side filter: the same family alternation the
// rule grades, matching anywhere in the line like grep -E.
var kallsymsRe = regexp.MustCompile(rootkitSyms)

// nativeKallsyms mirrors kallsymsScript: the symbol table narrowed to the
// rootkit families in process; no hit stays empty and quiet.
func nativeKallsyms(ctx context.Context) (string, error) {
	data, err := os.ReadFile("/proc/kallsyms")
	if err != nil {
		return "", model.ErrTierUnavailable
	}
	var b strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		if kallsymsRe.MatchString(line) {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String(), nil
}

// nativeProcModules reads the module registry the cat tier reads.
func nativeProcModules(ctx context.Context) (string, error) {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return "", model.ErrTierUnavailable
	}
	return string(data), nil
}

// nativeLsmod formats /proc/modules as the lsmod table — header included, so
// the lsmod lexer reads both channels' output the same way. The fourth
// /proc/modules field is the dependent-module list or "-".
func nativeLsmod(ctx context.Context) (string, error) {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return "", model.ErrTierUnavailable
	}
	var b strings.Builder
	b.WriteString("Module                  Size  Used by\n")
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		used := ""
		if len(f) >= 4 && f[3] != "-" {
			used = f[3]
		}
		fmt.Fprintf(&b, "%-20s %8s %2s %s\n", f[0], f[1], f[2], used)
	}
	return b.String(), nil
}

// nativeTainted reads the taint mask. procfs.KernelTainted covers the same file
// but is Linux-only, and this tier is defined on every platform (it reports
// itself unavailable where /proc is absent); the file holds one integer, so it
// is read directly.
func nativeTainted(ctx context.Context) (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/tainted")
	if err != nil {
		return "", model.ErrTierUnavailable
	}
	return string(data), nil
}

// nativeModuleSig mirrors moduleSigScript: the ikconfig dump first, the
// /boot/config-<release> fallback second, both narrowed to CONFIG_MODULE_SIG;
// an empty answer stays silent on a custom kernel.
func nativeModuleSig(ctx context.Context) (string, error) {
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
	var b strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CONFIG_MODULE_SIG") {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}
