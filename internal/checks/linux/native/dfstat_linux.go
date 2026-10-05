// df's statfs source. The mount table itself comes from /proc, so the statfs
// numbers only matter on Linux; elsewhere the tier reports unavailable and the
// local channel falls back to the host's df.

//go:build linux

package native

import "golang.org/x/sys/unix"

// statfsBlocks returns one path's total, used, and available bytes; ok is
// false when statfs itself failed (an unmounted placeholder, a raced mount).
func statfsBlocks(path string) (total, used, avail uint64, ok bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, 0, 0, false
	}
	bs := uint64(st.Bsize)
	total = uint64(st.Blocks) * bs
	used = (uint64(st.Blocks) - uint64(st.Bfree)) * bs
	avail = uint64(st.Bavail) * bs
	return total, used, avail, true
}
