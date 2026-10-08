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

// Free renders `free`'s table from /proc/meminfo: the header, the Mem row and the
// Swap row, in the widths and the unit procps prints them in.
//
// The numbers are procps' own reading of the file: buff/cache is Buffers +
// Cached + SReclaimable, shared is Shmem, and used is the total minus the
// MemAvailable figure. That last one is a definition the tool changed: procps 4
// derives it from MemAvailable, while 3.3 subtracted free and buff/cache — so an
// older target prints its own arithmetic on its row, and the header names the
// column either way. A kernel that states no available figure, or an impossible
// one, gets the second reading.
//
// The unit is the file's own: KiB, the spelling plain `free` prints and the one
// every procps carries, where free -h's scaling differs between 3.3 (which
// truncates a cell to whole units) and 4.0 (which rounds it).
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

// freeTable renders free's table from one /proc/meminfo reading. An empty answer
// is a reading without a total: a kernel that does not report the file's first
// figure has no memory view to print.
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
		// A kernel that states no available figure (pre-3.14), or an impossible
		// one, gets the reading the file does support: what is free plus what the
		// page cache could give back. The subtraction below then lands on the
		// definition procps 3.3 used, total minus free minus buff/cache.
		available = free + cache
	}
	used := max(total-available, 0)
	swapTotal, swapFree := kib(mi.SwapTotal), kib(mi.SwapFree)
	var b strings.Builder
	// The label column is eight cells, every number cell twelve, right-aligned:
	// free's own layout, so the header words land over the columns they name.
	fmt.Fprintf(&b, "%-8s%12s%12s%12s%12s%12s%12s\n",
		"", "total", "used", "free", "shared", "buff/cache", "available")
	fmt.Fprintf(&b, "%-8s%12d%12d%12d%12d%12d%12d\n", "Mem:",
		total, used, free, kib(mi.Shmem), cache, available)
	fmt.Fprintf(&b, "%-8s%12d%12d%12d\n", "Swap:",
		swapTotal, swapTotal-swapFree, swapFree)
	return b.String()
}
