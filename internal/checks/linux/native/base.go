// native_base holds the shared building blocks of the local tier that reach
// outside the filesystem: running a host binary, answering the shell's
// `command -v` guard, and walking /proc's pid entries. Every helper reproduces
// its shell-tier counterpart's text exactly, so the rules, filters, and lexers
// apply to both tiers unchanged.
//
// The filesystem work itself — path word lists, listings, walks, file reads,
// the file(1) classification — lives in internal/localfs, and the /proc, sysfs,
// netlink and utmp interfaces in this package's own files.

package native

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// hostResult is one host command's stdout plus whether it exited zero: the
// script tier's `cmd || next` ladders decide on the exit code while its
// `2>/dev/null` pipes keep stdout only, and output already written survives a
// timeout (harvest semantics).
type hostResult struct {
	out string
	ok  bool
}

// runHost execs one host command without a shell; the variable is swapped in
// tests. cLocale pins ls -l month names to the C spelling, the locale the
// script tier sets with LC_ALL=C.
var runHost = defaultRunHost

func defaultRunHost(ctx context.Context, argv []string, cLocale bool) hostResult {
	if len(argv) == 0 {
		return hostResult{}
	}
	if _, err := exec.LookPath(argv[0]); err != nil {
		return hostResult{}
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if cLocale {
		cmd.Env = append(os.Environ(), "LC_ALL=C")
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return hostResult{out: out.String(), ok: err == nil}
}

// haveBinary mirrors the scripts' `command -v` guards: the ladder decides
// availability itself instead of declaring Requires, so the runner keeps
// falling through within the one native tier.
func haveBinary(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// numericName is /proc's own name test: an entry whose name is all digits is a
// pid (or a thread id), everything else is a kernel interface. One predicate for
// the pid listings, so the two views cannot disagree about what a process is.
func numericName(name string) (int, bool) {
	if name == "" {
		return 0, false
	}
	for _, c := range name {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	value, err := strconv.Atoi(name)
	return value, err == nil
}

// procPIDs lists /proc's numeric entries in lexical order — the order the
// scripts' /proc/[0-9]* globs expand to.
func procPIDs() []string {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []string
	for _, entry := range entries {
		if _, ok := numericName(entry.Name()); ok {
			pids = append(pids, entry.Name())
		}
	}
	return pids
}

// filteredLines is the in-process counterpart of the scripts' grep over a file
// it has already read: the lines keep accepts, in order, one newline each. No
// hit is an empty string rather than one empty line.
func filteredLines(data string, keep func(line string) bool) string {
	var b strings.Builder
	for _, line := range strings.Split(data, "\n") {
		if keep(line) {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}
