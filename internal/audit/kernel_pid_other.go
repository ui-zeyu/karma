//go:build !unix

package audit

// pidAlive has no pid-space question to ask outside a Unix kernel; the kernel
// domain's /proc reads are empty there too.
func pidAlive(int) bool { return false }
