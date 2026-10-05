// stat fields for the darwin build: the same numbers, field names macOS spells
// with a Timespec suffix. The Linux catalog's local tiers answer unavailable
// without /proc anyway; this file exists so the package compiles everywhere.

//go:build darwin

package localfs

import (
	"os"
	"syscall"
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

// StatOf reads the fields os.FileInfo does not carry.
func StatOf(info os.FileInfo) Stat {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		now := info.ModTime()
		return Stat{Nlink: 1, Mtime: now, Ctime: now, Atime: now}
	}
	return Stat{
		Nlink: int(st.Nlink),
		UID:   int(st.Uid),
		GID:   int(st.Gid),
		Mtime: time.Unix(st.Mtimespec.Sec, st.Mtimespec.Nsec),
		Ctime: time.Unix(st.Ctimespec.Sec, st.Ctimespec.Nsec),
		Atime: time.Unix(st.Atimespec.Sec, st.Atimespec.Nsec),
		Dev:   uint64(st.Dev),
	}
}
