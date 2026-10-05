// The kernel release on unix hosts, from the uname syscall the shell's uname
// -r goes through (x/sys/unix: stdlib syscall has no Uname binding on darwin).

//go:build unix

package facts

import (
	"strings"

	"golang.org/x/sys/unix"
)

func localKernel() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return ""
	}
	return charsToString(uts.Release[:])
}

// charsToString reads a Utsname release field (int8 on some platforms, byte
// on others) into a Go string.
func charsToString[T ~int8 | ~byte](field []T) string {
	bytes := make([]byte, 0, len(field))
	for _, c := range field {
		if c == 0 {
			break
		}
		bytes = append(bytes, byte(c))
	}
	return strings.TrimSpace(string(bytes))
}
