//go:build !unix

package localfs

import "os"

// openRegular is the plain open where the platform has no O_NONBLOCK: the hang
// it guards against is a POSIX one (a Windows named pipe is reached by name,
// and a filesystem FIFO does not exist there).
func openRegular(path string) (*os.File, error) {
	return os.Open(path)
}
