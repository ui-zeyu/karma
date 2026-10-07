// File capabilities on the platforms whose syscall layer has no xattr read: the
// tier reports itself unavailable, so the check is skipped there. The sh source's
// own `getcap -r /` is not on a local walk: a local run reads with the native
// source.

//go:build !linux

package native

// capsInProcess reports whether this build can read file capabilities itself.
func capsInProcess() bool { return false }

// fileCapsRow finds no capabilities without the xattr syscall.
func fileCapsRow(string) string { return "" }
