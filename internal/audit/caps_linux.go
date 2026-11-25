//go:build linux

package audit

import "golang.org/x/sys/unix"

func hasCaps(path string) bool {
	buf := make([]byte, 64)
	size, err := unix.Lgetxattr(path, "security.capability", buf)
	return err == nil && size > 0
}
