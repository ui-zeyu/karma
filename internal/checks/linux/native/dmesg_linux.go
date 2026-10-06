// dmesg's native tier: the kernel ring buffer through syslog(2), the same
// syscall the dmesg binary issues. Linux-only; other platforms take the
// unavailable stub.

//go:build linux

package native

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"

	"karma/internal/model"
)

// Dmesg reads the whole ring buffer the way the dmesg binary does:
// SYSLOG_ACTION_SIZE_BUFFER sizes the read, then READ_ALL fills it. A denied
// read (dmesg_restrict, a container without CAP_SYSLOG) is a failure the panel
// names: the buffer is there and this account was refused it, which is worth
// saying. The tier is unavailable only where syslog(2) itself is.
func Dmesg(ctx context.Context) (string, error) {
	size, err := unix.Klogctl(10 /* SYSLOG_ACTION_SIZE_BUFFER */, nil)
	if err != nil || size <= 0 {
		return "", klogError(err)
	}
	buf := make([]byte, size)
	n, err := unix.Klogctl(3 /* SYSLOG_ACTION_READ_ALL */, buf)
	if err != nil {
		return "", klogError(err)
	}
	return stripSyslogPriority(string(buf[:n])), nil
}

// klogError says why the ring buffer could not be read: a permission this
// account does not have is a failure with the reason, anything else (no
// syslog(2), a kernel that reports no buffer) leaves the tier unavailable.
func klogError(err error) error {
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		return fmt.Errorf("the kernel ring buffer is not readable by this account: %w", err)
	}
	return model.ErrTierUnavailable
}
