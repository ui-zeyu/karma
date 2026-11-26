// File reads: the cat reader and the non-blocking regular-file open.

package localfs

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrNotRegular is what a reader reports for a path that holds no bytes to give
// on its own: a FIFO, a device, a socket, or a directory. A caller that has a
// user-facing vocabulary of its own phrases the kind itself (cli.readError names
// the operand), so the kind travels as a value rather than as text to parse.
var ErrNotRegular = errors.New("not a regular file")

// Cat prints a file exactly as the kernel returned it, from karma's own read
// rather than the host's cat, so a preload hook on the host binary cannot
// reshape the answer.
//
// Only a regular file is read, and the open is the non-blocking one: a FIFO
// cannot park this process in open(2), and a path that is not a regular file is
// reported rather than read.
func Cat(path string) ([]byte, error) {
	file, err := Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}

// Open opens a regular file for reading without ever blocking in open(2). It
// is the one opener every reader of host files uses: a FIFO, device or
// directory is refused after the non-blocking open, so a planted special file
// cannot park a collector.
func Open(path string) (*os.File, error) {
	file, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("%s: %w", path, ErrNotRegular)
	}
	return file, nil
}

// ReadFile reads at most limit bytes of a regular file. A limit of zero or
// less reads the whole file.
func ReadFile(path string, limit int64) ([]byte, error) {
	file, err := Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if limit > 0 {
		return io.ReadAll(io.LimitReader(file, limit))
	}
	return io.ReadAll(file)
}
