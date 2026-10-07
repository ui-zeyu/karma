// uname's native tier: the utsname fields from the uname(2) syscall, the same
// call the uname binary issues. Linux-only — another platform's uname -a has
// its own field set, and the host's own binary spells that one.

//go:build linux

package native

import (
	"strings"

	"golang.org/x/sys/unix"

	"karma/internal/textutil"
)

// unameAll composes `uname -a`: kernel name, node, release, version, machine,
// and the operating-system field coreutils prints on Linux. ok is false when
// the syscall fails, which the sh source then answers.
func unameAll() (string, bool) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return "", false
	}
	fields := []string{
		textutil.CString(uts.Sysname[:]), textutil.CString(uts.Nodename[:]),
		textutil.CString(uts.Release[:]), textutil.CString(uts.Version[:]),
		textutil.CString(uts.Machine[:]), "GNU/Linux",
	}
	return strings.Join(fields, " ") + "\n", true
}
