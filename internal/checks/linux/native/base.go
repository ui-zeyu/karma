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
	"io"
	"karma/internal/model"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// hostResult is one host command's stdout plus whether it exited zero: a
// ladder decides on the exit code, a caller that asked for a quiet run keeps
// stdout only, and output already written survives a timeout (harvest
// semantics).
type hostResult struct {
	out string
	ok  bool
}

// runHost execs one host command without a shell; the variable is swapped in
// tests. cLocale pins ls -l month names to the C spelling, so a row's date does
// not follow the host's locale.
var runHost = defaultRunHost

func defaultRunHost(ctx context.Context, argv []string, cLocale bool) hostResult {
	return execHost(ctx, argv, cLocale, false)
}

// runHostQuiet is runHost with the command's standard error dropped: dpkg -S
// writes a complaint for every pattern
// that matches no file, and those complaints belong in neither the panel nor
// karma's own error stream.
func runHostQuiet(ctx context.Context, argv []string, cLocale bool) hostResult {
	return execHost(ctx, argv, cLocale, true)
}

// Host runs one host command as a tier body of its own: a surface the sh source
// spells as a shell command and the in-process source runs directly. A binary the
// host lacks reports the tier unavailable, the way a missing command's 127 does
// on the other side, so the section simply is not there.
func Host(argv ...string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		result := runHostQuiet(ctx, argv, false)
		if !result.ok {
			return "", model.ErrTierUnavailable
		}
		return result.out, nil
	}
}

func execHost(ctx context.Context, argv []string, cLocale, quiet bool) hostResult {
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
	if quiet {
		cmd.Stderr = io.Discard
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return hostResult{out: out.String(), ok: err == nil}
}

// haveBinary is a tier's own availability test — the `command -v` guard a
// shell script writes: a body that needs a host tool asks for it when it runs
// rather than declaring it up front, and reports ErrTierUnavailable when the
// host has none.
func haveBinary(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// procFile reads one kernel interface whole. An interface that cannot be read
// is the same answer a missing host tool gives — the tier cannot run here, and
// the chain falls through — so /proc on a host without it, a container that
// hides the file and a permission the run does not hold are one outcome.
//
// The read is a plain os.ReadFile: /proc and /sys entries are the one place
// localfs's non-blocking open is not used, because the interface's own read
// semantics are what the tier is reading (see localfs's package comment).
func procFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", model.ErrTierUnavailable
	}
	return string(data), nil
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

// filteredLines keeps the lines of a body it has already read, in order, one
// newline each. No hit is an empty string rather than one empty line.
func filteredLines(data string, keep func(line string) bool) string {
	var b strings.Builder
	for line := range strings.SplitSeq(data, "\n") {
		if keep(line) {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}
