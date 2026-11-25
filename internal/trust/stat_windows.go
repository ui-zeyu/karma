package trust

import "io/fs"

func statOwner(fs.FileInfo) (uid, gid int) { return -1, -1 }

func statMeta(info fs.FileInfo) (ctime int64, inode uint64) {
	return info.ModTime().Unix(), 0
}
