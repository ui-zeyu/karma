// native tiers of the system checks: distro facts, uptime, clock, and the
// environment, read in-process.

package native

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/procfs"

	"karma/internal/localfs"
	"karma/internal/model"
)

// OsRelease reads the distro file (lsb_release when missing), a blank line, then
// uname -a from the uname syscall (native_uname).
// A platform without that spelling reports the tier unavailable and the shell
// ladder answers, so the check reads either way.
func OsRelease(ctx context.Context) (string, error) {
	unameText, ok := unameAll()
	if !ok {
		return "", model.ErrTierUnavailable
	}
	text := ""
	if body, err := localfs.ReadRegular("/etc/os-release"); err == nil {
		text = string(body)
	} else if res := runHost(ctx, []string{"lsb_release", "-a"}, false); res.out != "" {
		text = res.out
	}
	return text + "\n" + unameText, nil
}

// ProcUptime reads /proc/uptime directly: the banner tier comes first in either
// source's walk, so this is the minimal-system fallback — the file the banner
// itself is derived from.
func ProcUptime(ctx context.Context) (string, error) {
	return procFile("/proc/uptime")
}

// uptimeBannerLine is the banner `uptime` and `w` print: clock, up span,
// live sessions, load averages. procps spells it with a leading space.
func uptimeBannerLine() string {
	return " " + uptimeBannerBody()
}

// uptimeBannerBody is the banner without that leading space — top prints the
// same text behind its "top - " prefix.
func uptimeBannerBody() string {
	users := userCount()
	plural := "users"
	if users == 1 {
		plural = "user"
	}
	return fmt.Sprintf("%s up %s, %2d %s,  load average: %s",
		time.Now().Format("15:04:05"), upDuration(readProcUptime()), users, plural, readLoadavg())
}

// userCount is procps' procps_users(): the sessions logind reports when the
// host runs systemd, otherwise the utmp USER_PROCESS records. Reading
// /run/systemd/sessions keeps the count in process; a host without that
// directory (or with an empty session list) falls back to utmp.
func userCount() int {
	if count, ok := logindUserCount(); ok {
		return count
	}
	if recs, ok, _ := readUtmpRecords("/var/run/utmp"); ok {
		return len(userRecords(recs))
	}
	return 0
}

// logindUserCount counts logind's sessions of class "user" — "user",
// "user-early" and "user-incomplete" all count, the same prefix test procps
// makes with strncmp(class, "user", 4). ok is false when this host has no
// session directory or logind reports no session at all.
func logindUserCount() (int, bool) {
	return logindSessionsIn("/run/systemd/sessions")
}

// logindSessionsIn is that count over a given directory, the one the tests
// substitute a fixture for. Systemd 255+ also drops each live session's
// reference FIFO here (<audit-id>.ref): logind watches its end for hangup, and
// a reader that opens the other end blocks forever — a block no tier timeout
// can interrupt, since the in-process bodies time out cooperatively. Only the
// plain state files carry the CLASS= line, so everything that is not a regular
// file is skipped before it is ever opened.
func logindSessionsIn(dir string) (int, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		return 0, false
	}
	count := 0
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		if sessionIsUser(data) {
			count++
		}
	}
	return count, true
}

// sessionIsUser reports whether one logind session file describes a user
// session. A file without a CLASS line (or one whose class is a manager
// session) counts as no.
func sessionIsUser(data []byte) bool {
	for line := range strings.SplitSeq(string(data), "\n") {
		if class, found := strings.CutPrefix(line, "CLASS="); found {
			return strings.HasPrefix(class, "user")
		}
	}
	return false
}

// upDuration spells uptime's elapsed column the way procps does: days, then
// either "H:MM" (hours right-aligned in two cells, minutes zero-padded) or,
// within the first day, whole minutes.
func upDuration(secs float64) string {
	totalMin := int(secs) / 60
	days, rem := totalMin/1440, totalMin%1440
	h, m := rem/60, rem%60
	var b strings.Builder
	comma := false
	item := func(n int, unit string) {
		if comma {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%d %s", n, unit)
		comma = true
	}
	if days > 0 {
		if days == 1 {
			item(1, "day")
		} else {
			item(days, "days")
		}
	}
	if h > 0 {
		if comma {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%2d:%02d", h, m)
	} else {
		item(m, "min")
	}
	return b.String()
}

// readLoadavg returns loadavg's three averages, read through procfs.
func readLoadavg() string {
	avg, err := procFS().LoadAvg()
	if err != nil {
		return "0.00, 0.00, 0.00"
	}
	return fmt.Sprintf("%.2f, %.2f, %.2f", avg.Load1, avg.Load5, avg.Load15)
}

// Uptime mirrors `uptime` from /proc/uptime and /proc/loadavg.
func Uptime(ctx context.Context) (string, error) {
	if _, err := os.Stat("/proc/uptime"); err != nil {
		return "", model.ErrTierUnavailable
	}
	return uptimeBannerLine() + "\n", nil
}

// Date mirrors `date`.
func Date(ctx context.Context) (string, error) {
	return time.Now().Format("Mon Jan _2 15:04:05 MST 2006") + "\n", nil
}

// Env mirrors `env`, sorted so two collections of the same host diff
// cleanly.
func Env(ctx context.Context) (string, error) {
	lines := os.Environ()
	slices.Sort(lines)
	return strings.Join(lines, "\n") + "\n", nil
}

// Free renders `free -h`'s table from /proc/meminfo: the header, the Mem row and
// the Swap row, in the widths and the units procps prints them in.
//
// The numbers are procps' own reading of the file — its meminfo library's
// arithmetic, which is what the target's own free does with the same bytes:
// buff/cache is Buffers + Cached + SReclaimable, shared is Shmem, used is the
// total minus the available figure, and a kernel that states none (pre-3.14) or
// an impossible one has that figure taken from MemFree. The one figure procps 3.3
// reads differently is used: it subtracted free and buff/cache instead, so an old
// target prints its own arithmetic on its row, and the header names the column
// either way.
//
// The human spelling is procps 4's (freeScale). procps 3.3's -h differs twice
// over: it truncates the reading to whole mebibytes before scaling, so it prints
// 0.0Ki for anything under one and drops the tenth of its mebibyte rows — a host
// that old prints its own digits on its own row, which is the sh source's
// evidence either way.
func Free(ctx context.Context) (string, error) {
	mi, err := procFS().Meminfo()
	if err != nil {
		return "", model.ErrTierUnavailable
	}
	table := freeTable(&mi)
	if table == "" {
		return "", model.ErrTierUnavailable
	}
	return table, nil
}

// freeUnits are the binary prefixes free -h scales through, in procps' order.
var freeUnits = []string{"Ki", "Mi", "Gi", "Ti", "Pi", "Ei"}

// freeScale renders one /proc/meminfo cell the way procps 4's free -h does: the
// first spelling that fits the column, which is why the mebibyte count of a
// large figure is an integer (976Mi) while a small one keeps its tenth (4.2Mi),
// and why a value the largest unit cannot hold in five cells keeps the exbibyte
// count. The scale is the tool's own — a float, not a double, before printing —
// so a host running the same procps prints the same digits.
//
// The name is free's own: df's humanKiB above is coreutils' spelling, which
// rounds up at the printed precision, where this one keeps the digits the tool
// itself would print.
func freeScale(kib int64) string {
	bytes := float64(kib) * 1024
	if bare := fmt.Sprintf("%dB", kib*1024); len(bare) <= 4 {
		return bare
	}
	out := ""
	scale := 1024.0
	for _, unit := range freeUnits {
		scaled := bytes / scale
		if tenths := fmt.Sprintf("%.1f%s", float32(scaled), unit); len(tenths) <= 5 {
			return tenths
		}
		out = fmt.Sprintf("%d%s", int64(scaled), unit)
		if len(out) <= 5 {
			return out
		}
		scale *= 1024
	}
	return out
}

// freeTable renders free -h's table from one /proc/meminfo reading. An empty
// answer is a reading without a total: a kernel that does not report the file's
// first figure has no memory view to print.
func freeTable(mi *procfs.Meminfo) string {
	kib := func(value *uint64) int64 {
		if value == nil {
			return 0
		}
		return int64(*value)
	}
	total := kib(mi.MemTotal)
	if total <= 0 {
		return ""
	}
	free, available := kib(mi.MemFree), kib(mi.MemAvailable)
	cache := kib(mi.Buffers) + kib(mi.Cached) + kib(mi.SReclaimable)
	if available <= 0 || available > total {
		// No available figure (pre-3.14), or one the file cannot mean: the
		// library reads MemFree in its place, the way a container's distorted
		// figures are handled.
		available = free
	}
	used := max(total-available, 0)
	swapTotal, swapFree := kib(mi.SwapTotal), kib(mi.SwapFree)
	var b strings.Builder
	// The label column is eight cells, every number cell twelve, right-aligned:
	// free's own layout, so the header words land over the columns they name.
	fmt.Fprintf(&b, "%-8s%12s%12s%12s%12s%12s%12s\n",
		"", "total", "used", "free", "shared", "buff/cache", "available")
	fmt.Fprintf(&b, "%-8s%12s%12s%12s%12s%12s%12s\n", "Mem:",
		freeScale(total), freeScale(used), freeScale(free), freeScale(kib(mi.Shmem)),
		freeScale(cache), freeScale(available))
	fmt.Fprintf(&b, "%-8s%12s%12s%12s\n", "Swap:",
		freeScale(swapTotal), freeScale(max(swapTotal-swapFree, 0)), freeScale(swapFree))
	return b.String()
}
