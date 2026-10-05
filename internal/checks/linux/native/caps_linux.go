// Linux file capabilities read in process: the security.capability xattr is
// the same record getcap reads, decoded here so no hook inside libcap can
// reshape what the local channel reports.

//go:build linux

package native

import (
	"encoding/binary"

	"golang.org/x/sys/unix"
)

const (
	securityCapability = "security.capability"

	// struct vfs_cap_data: the low byte of magic_etc carries the flags, the top
	// byte the revision; revisions 2 and 3 carry two 32-bit words per set.
	vfsCapFlagsEffective = 0x000001
	vfsCapRevisionMask   = 0xff000000
	vfsCapRevision2      = 0x02000000
	vfsCapRevision3      = 0x03000000
)

// capsInProcess reports whether this build can read file capabilities itself.
func capsInProcess() bool { return true }

// fileCapsRow renders one file's capabilities in getcap's column shape ("path
// cap_a,cap_b=ep"), or "" when the file carries none. A filesystem without
// xattr support, or an unprivileged read of another user's file, yields no row
// — the same silence getcap shows.
func fileCapsRow(path string) string {
	buf := make([]byte, 24)
	n, err := unix.Lgetxattr(path, securityCapability, buf)
	if err != nil || n < 12 {
		return ""
	}
	data := buf[:n]
	magic := binary.LittleEndian.Uint32(data[0:4])
	permitted := uint64(binary.LittleEndian.Uint32(data[4:8]))
	inheritable := uint64(binary.LittleEndian.Uint32(data[8:12]))
	switch magic & vfsCapRevisionMask {
	case vfsCapRevision2, vfsCapRevision3:
		if len(data) < 20 {
			return ""
		}
		permitted |= uint64(binary.LittleEndian.Uint32(data[12:16])) << 32
		inheritable |= uint64(binary.LittleEndian.Uint32(data[16:20])) << 32
	}
	if permitted == 0 && inheritable == 0 {
		return ""
	}
	// VFS_CAP_FLAGS_EFFECTIVE: the written set is the effective set
	effective := uint64(0)
	if magic&vfsCapFlagsEffective != 0 {
		effective = permitted
	}
	text := capsText(permitted, inheritable, effective)
	if text == "" {
		return ""
	}
	return path + " " + text
}
