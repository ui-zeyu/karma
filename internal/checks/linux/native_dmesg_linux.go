// dmesg's native tier: the kernel ring buffer through syslog(2), the same
// syscall the dmesg binary issues. Linux-only; other platforms take the
// unavailable stub.

//go:build linux

package linux

import (
	"context"

	"golang.org/x/sys/unix"

	"karma/internal/model"
)

// nativeDmesg reads the whole ring buffer the way the dmesg binary does:
// SYSLOG_ACTION_SIZE_BUFFER sizes the read, then READ_ALL fills it. A denied
// read (dmesg_restrict, a container without CAP_SYSLOG) reports the tier
// unavailable, exactly like a failing dmesg binary on the script side.
func nativeDmesg(ctx context.Context) (string, error) {
	size, err := unix.Klogctl(10 /* SYSLOG_ACTION_SIZE_BUFFER */, nil)
	if err != nil || size <= 0 {
		return "", model.ErrTierUnavailable
	}
	buf := make([]byte, size)
	n, err := unix.Klogctl(3 /* SYSLOG_ACTION_READ_ALL */, buf)
	if err != nil {
		return "", model.ErrTierUnavailable
	}
	return stripSyslogPriority(string(buf[:n])), nil
}
