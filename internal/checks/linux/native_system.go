// native tiers of the system checks: distro facts, uptime, clock, and the
// environment, read in-process.

package linux

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"karma/internal/model"
)

// nativeOsRelease mirrors osReleaseScript: the distro file (lsb_release when
// missing), a blank line, then uname -a from the uname syscall (native_uname).
// A platform without that spelling reports the tier unavailable and the shell
// ladder answers, so the check reads either way.
func nativeOsRelease(ctx context.Context) (string, error) {
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

// nativeProcUptime reads /proc/uptime directly: the uptime binary stays the
// first tier on every channel, this is the minimal-system fallback.
func nativeProcUptime(ctx context.Context) (string, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "", model.ErrTierUnavailable
	}
	return string(data), nil
}

// uptimeBannerLine is the banner `uptime` and `w` print: clock, up span,
// live sessions, load averages.
func uptimeBannerLine() string {
	users := 0
	if recs, ok := readUtmpRecords("/var/run/utmp"); ok {
		users = len(userRecords(recs))
	}
	plural := "s"
	if users == 1 {
		plural = ""
	}
	return fmt.Sprintf("%s up %s, %d user%s, load average: %s",
		time.Now().Format("15:04:05"), upDuration(readProcUptime()), users, plural, readLoadavg())
}

// upDuration spells uptime's elapsed column: minutes under an hour, H:MM
// within the day, "N days, H:MM" beyond.
func upDuration(secs float64) string {
	totalMin := int(secs) / 60
	days, rem := totalMin/1440, totalMin%1440
	h, m := rem/60, rem%60
	switch {
	case days > 1:
		return fmt.Sprintf("%d days, %d:%02d", days, h, m)
	case days == 1:
		return fmt.Sprintf("1 day, %d:%02d", h, m)
	case h > 0:
		return fmt.Sprintf("%d:%02d", h, m)
	default:
		return fmt.Sprintf("%d min", m)
	}
}

// readLoadavg returns loadavg's three averages, read through procfs.
func readLoadavg() string {
	avg, err := procFS().LoadAvg()
	if err != nil {
		return "0.00, 0.00, 0.00"
	}
	return fmt.Sprintf("%.2f, %.2f, %.2f", avg.Load1, avg.Load5, avg.Load15)
}

// nativeUptime mirrors `uptime` from /proc/uptime and /proc/loadavg.
func nativeUptime(ctx context.Context) (string, error) {
	if _, err := os.Stat("/proc/uptime"); err != nil {
		return "", model.ErrTierUnavailable
	}
	return uptimeBannerLine() + "\n", nil
}

// nativeDate mirrors `date`.
func nativeDate(ctx context.Context) (string, error) {
	return time.Now().Format("Mon Jan _2 15:04:05 MST 2006") + "\n", nil
}

// nativeEnv mirrors `env`, sorted so two collections of the same host diff
// cleanly.
func nativeEnv(ctx context.Context) (string, error) {
	lines := os.Environ()
	slices.Sort(lines)
	return strings.Join(lines, "\n") + "\n", nil
}
