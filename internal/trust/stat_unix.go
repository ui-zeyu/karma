//go:build !windows

package trust

import (
	"io/fs"
	"syscall"
)

func statOwner(info fs.FileInfo) (uid, gid int) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, -1
	}
	return int(st.Uid), int(st.Gid)
}
