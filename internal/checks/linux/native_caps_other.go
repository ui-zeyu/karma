// File capabilities on the platforms whose syscall layer has no xattr read:
// the tier reports itself unavailable and the local channel runs the host's
// getcap, the same ladder every other platform-specific native uses.

//go:build !linux

package linux

// capsInProcess reports whether this build can read file capabilities itself.
func capsInProcess() bool { return false }

// fileCapsRow finds no capabilities without the xattr syscall.
func fileCapsRow(string) string { return "" }
