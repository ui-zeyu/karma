// uname's native tier on the platforms whose uname -a spells its own field
// set; there the shell tier asks the host's own uname instead.

//go:build !linux

package linux

// unameAll reports the tier unavailable: this platform's uname -a is not the
// Linux spelling the check collects.
func unameAll() (string, bool) { return "", false }
