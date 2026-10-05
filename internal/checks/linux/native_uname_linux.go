// uname's native tier: the utsname fields from the uname(2) syscall, the same
// call the uname binary issues. Linux-only — another platform's uname -a has
// its own field set, and the host's own binary spells that one.

//go:build linux

package linux

import (
	"strings"

	"golang.org/x/sys/unix"
)

// unameAll composes `uname -a`: kernel name, node, release, version, machine,
// and the operating-system field coreutils prints on Linux. ok is false when
// the syscall fails, which the shell tier then answers.
func unameAll() (string, bool) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return "", false
	}
	fields := []string{
		utsField(uts.Sysname[:]), utsField(uts.Nodename[:]),
		utsField(uts.Release[:]), utsField(uts.Version[:]),
		utsField(uts.Machine[:]), "GNU/Linux",
	}
	return strings.Join(fields, " ") + "\n", true
}

// utsField reads one utsname field (int8 on some architectures, byte on
// others) up to its terminator.
func utsField[T ~int8 | ~byte](field []T) string {
	var b strings.Builder
	for _, c := range field {
		if c == 0 {
			break
		}
		b.WriteByte(byte(c))
	}
	return strings.TrimSpace(b.String())
}
