// df's statfs stub for the platforms whose syscall layer has no Statfs. The
// tier reads /proc for the mount table and never reaches these numbers there.

//go:build !linux

package linux

// statfsBlocks is unavailable without statfs(2).
func statfsBlocks(path string) (total, used, avail uint64, ok bool) {
	return 0, 0, 0, false
}
