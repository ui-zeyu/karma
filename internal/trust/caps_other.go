//go:build !linux

package trust

func fileCaps(string) bool { return false }
