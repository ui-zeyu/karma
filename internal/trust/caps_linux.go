//go:build linux

package trust

import "golang.org/x/sys/unix"

// fileCaps reports a file capability on path. The xattr is the authority the
// kernel grants on exec, and it is not part of the mode word.
func fileCaps(path string) bool {
	buf := make([]byte, 64)
	size, err := unix.Lgetxattr(path, "security.capability", buf)
	return err == nil && size > 0
}
