//go:build darwin

package trust

import (
	"io/fs"
	"syscall"
)

func statMeta(info fs.FileInfo) (ctime int64, inode uint64) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0
	}
	return st.Ctimespec.Sec, st.Ino
}
