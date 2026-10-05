// stat fields the local row shape reads beyond os.FileInfo on Linux: link
// count, owner ids, change time (find's %C@ has no portable FileInfo
// equivalent), and the device id -xdev compares. All come from syscall.Stat_t.

//go:build linux

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

// StatOf reads the fields os.FileInfo does not carry. A FileInfo from another
// source (a synthesized one in a test, an exotic filesystem) falls back to the
// modification time for all three stamps and one link.
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
		Mtime: time.Unix(st.Mtim.Sec, st.Mtim.Nsec),
		Ctime: time.Unix(st.Ctim.Sec, st.Ctim.Nsec),
		Atime: time.Unix(st.Atim.Sec, st.Atim.Nsec),
		Dev:   uint64(st.Dev),
	}
}
