// stat fields for platforms whose syscall layer offers no Stat_t here: link
// count 1, ctime equal to mtime, one device. Only build coverage needs this
// file; the Linux catalog's local tiers run where /proc exists.

//go:build !linux && !darwin

package localfs

import (
	"os"
	"time"
)

// Stat is what the find -printf conversions need from one lstat.
type Stat struct {
	Nlink int
	UID   int
	GID   int
	Mtime time.Time
	Ctime time.Time
	Atime time.Time
	Dev   uint64
}

// StatOf reads the fields os.FileInfo does not carry; without Stat_t only the
// modification time is there to read.
func StatOf(info os.FileInfo) Stat {
	now := info.ModTime()
	return Stat{Nlink: 1, Mtime: now, Ctime: now, Atime: now}
}
