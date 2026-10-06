//go:build unix

package localfs

import (
	"os"
	"syscall"
)

// openRegular opens a path for reading without ever blocking in open(2). A
// FIFO or device node whose other end never arrives would otherwise park the
// calling goroutine forever, and nothing above this layer can end that park: the
// local channel's tier deadline abandons a body parked in a syscall rather than
// breaking it, SIGINT/SIGTERM reach no goroutine, and the tier then answers with
// what it had. O_NONBLOCK is a no-op for a regular file — every ordinary read is
// unchanged — while a FIFO's open returns at once and its read reports end of
// file instead of waiting.
//
// This is the layer's one guarantee: a host path can be named by a page or a
// caller without karma's own process ever parking on it. Every read of a host
// file goes through here (ReadRegular, Cat, Tail, grepFile), so the guarantee
// cannot be lost by a new call site forgetting it. Kernel pseudo-files (/proc,
// /sys) are the deliberate exception: they have no FIFO semantics.
func openRegular(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
