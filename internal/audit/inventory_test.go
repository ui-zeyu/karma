package audit

import "testing"

func TestFormatSibling(t *testing.T) {
	file := UnownedFile{Dir: "/usr/bin", Total: 100, Owned: 99}
	got := formatSibling(file)
	if got == "" || got == "the directory has no package-owned peer count" {
		t.Errorf("formatSibling = %q", got)
	}
}
