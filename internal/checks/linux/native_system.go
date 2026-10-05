// native tiers of the system checks: distro facts and /proc/uptime.

package linux

import (
	"context"
	"os"

	"karma/internal/model"
)

// nativeOsRelease mirrors osReleaseScript: the distro file (lsb_release when
// missing), a blank line, then uname -a.
func nativeOsRelease(ctx context.Context) (string, error) {
	text := ""
	if body, err := os.ReadFile("/etc/os-release"); err == nil {
		text = string(body)
	} else if res := runHost(ctx, []string{"lsb_release", "-a"}, false); res.out != "" {
		text = res.out
	}
	return text + "\n" + runHost(ctx, []string{"uname", "-a"}, false).out, nil
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
