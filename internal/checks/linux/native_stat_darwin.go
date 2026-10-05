// stat fields for the darwin build: the same numbers, field names macOS spells
// with a Timespec suffix. The Linux catalog's native tier answers unavailable
// without /proc anyway; this file exists so the package compiles everywhere.

//go:build darwin

package linux

import (
	"os"
	"syscall"
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
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		now := info.ModTime()
		return statFields{nlink: 1, mtime: now, ctime: now, atime: now}
	}
	return statFields{
		nlink: int(st.Nlink),
		uid:   int(st.Uid),
		gid:   int(st.Gid),
		mtime: time.Unix(st.Mtimespec.Sec, st.Mtimespec.Nsec),
		ctime: time.Unix(st.Ctimespec.Sec, st.Ctimespec.Nsec),
		atime: time.Unix(st.Atimespec.Sec, st.Atimespec.Nsec),
		dev:   uint64(st.Dev),
	}
}
