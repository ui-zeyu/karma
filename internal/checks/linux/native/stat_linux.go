// stat fields the native tier reads beyond os.FileInfo on Linux: link count,
// owner ids, change time (find's %C@ has no portable FileInfo equivalent), and
// the device id -xdev compares. All come from syscall.Stat_t.

//go:build linux

package native

import (
	"os"
	"syscall"
	"time"
)

// statFields is what the find -printf conversions need from one lstat.
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
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		now := info.ModTime()
		return statFields{nlink: 1, mtime: now, ctime: now, atime: now}
	}
	return statFields{
		nlink: int(st.Nlink),
		uid:   int(st.Uid),
		gid:   int(st.Gid),
		mtime: time.Unix(st.Mtim.Sec, st.Mtim.Nsec),
		ctime: time.Unix(st.Ctim.Sec, st.Ctim.Nsec),
		atime: time.Unix(st.Atim.Sec, st.Atim.Nsec),
		dev:   uint64(st.Dev),
	}
}
