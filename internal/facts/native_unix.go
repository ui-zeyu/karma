// The kernel release on unix hosts, from the uname syscall the shell's uname
// -r goes through (x/sys/unix: stdlib syscall has no Uname binding on darwin).

//go:build unix

package facts

import (
	"golang.org/x/sys/unix"

	"karma/internal/textutil"
)

func localKernel() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return ""
	}
	return textutil.CString(uts.Release[:])
}
