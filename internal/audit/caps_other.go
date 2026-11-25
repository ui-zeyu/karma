//go:build !linux

package audit

func hasCaps(string) bool { return false }
