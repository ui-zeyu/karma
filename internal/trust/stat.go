package trust

import (
	"io/fs"
	"os"
)

// CTime answers one stat result's inode change time. It never follows a
// second path, so a walker can ask the entry it already read.
func CTime(info fs.FileInfo) int64 {
	ctime, _ := statMeta(info)
	return ctime
}

// StatMeta stats one path and answers its inode change time and number: the
// same facts Facts carries, for paths outside a judged set (a package ledger's
// own files, whose change time is itself evidence).
func StatMeta(path string) (ctime int64, inode uint64, ok bool) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0, false
	}
	ctime, inode = statMeta(info)
	return ctime, inode, ctime != 0 || inode != 0
}
