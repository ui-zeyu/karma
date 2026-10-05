// stat fields for platforms whose syscall layer offers no Stat_t here: link
// count 1, ctime equal to mtime, one device. Only build coverage needs this
// file; the native tier runs where /proc exists.

//go:build !linux && !darwin

package native

import (
	"os"
	"time"
)

type statFields struct {
	nlink int
	uid   int
	gid   int
	mtime time.Time
	ctime time.Time
	atime time.Time
	dev   uint64
}

func statOf(info os.FileInfo) statFields {
	now := info.ModTime()
	return statFields{nlink: 1, mtime: now, ctime: now, atime: now}
}
