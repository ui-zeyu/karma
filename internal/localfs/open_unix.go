//go:build unix

package localfs

import (
	"os"
	"syscall"
)

// openRegular opens a path for reading without ever blocking in open(2). A
// FIFO or device node whose other end never arrives would otherwise park the
// calling goroutine forever: the local channel's tiers time out cooperatively,
// so neither a tier deadline nor SIGINT/SIGTERM can break such an open, and the
// whole collection hangs until SIGKILL. O_NONBLOCK is a no-op for a regular
// file — every ordinary read is unchanged — while a FIFO's open returns at once
// and its read reports end of file instead of waiting.
//
// The callers that hand it a host-writable path (a log, one of the utmp
// records, /etc/passwd, a boot config, a path a package verifier listed) are
// the reason this exists: a planted FIFO must be evidence, not a hang.
func openRegular(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
