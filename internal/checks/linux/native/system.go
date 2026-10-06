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

	"karma/internal/model"
)

// OsRelease mirrors osReleaseScript: the distro file (lsb_release when
// missing), a blank line, then uname -a from the uname syscall (native_uname).
// A platform without that spelling reports the tier unavailable and the shell
// ladder answers, so the check reads either way.
func OsRelease(ctx context.Context) (string, error) {
	unameText, ok := unameAll()
	if !ok {
		return "", model.ErrTierUnavailable
	}
	text := ""
	if body, err := os.ReadFile("/etc/os-release"); err == nil {
		text = string(body)
	} else if res := runHost(ctx, []string{"lsb_release", "-a"}, false); res.out != "" {
		text = res.out
	}
	return text + "\n" + unameText, nil
}

// ProcUptime reads /proc/uptime directly: the uptime binary stays the
// first tier on every channel, this is the minimal-system fallback.
func ProcUptime(ctx context.Context) (string, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "", model.ErrTierUnavailable
	}
	return string(data), nil
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
	if recs, ok := readUtmpRecords("/var/run/utmp"); ok {
		return len(userRecords(recs))
	}
	return 0
}

// logindUserCount counts logind's sessions of class "user" — "user",
// "user-early" and "user-incomplete" all count, the same prefix test procps
// makes with strncmp(class, "user", 4). ok is false when this host has no
// session directory or logind reports no session at all.
func logindUserCount() (int, bool) {
	entries, err := os.ReadDir("/run/systemd/sessions")
	if err != nil || len(entries) == 0 {
		return 0, false
	}
	count := 0
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join("/run/systemd/sessions", entry.Name()))
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
