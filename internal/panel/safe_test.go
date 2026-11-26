package panel

import (
	"strings"
	"testing"
)

func TestSafeTextRemovesTerminalControl(t *testing.T) {
	input := "a\x1b[2Jb\x1b]0;title\x07c\r\nd\te\x7ff\x9b31m"
	got := SafeText(input)
	for _, forbidden := range []string{"\x1b", "\x07", "\r", "\n", "\t", "\x7f", "\x9b"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("SafeText kept %q in %q", forbidden, got)
		}
	}
	if !strings.Contains(got, "a") || !strings.Contains(got, "b") || !strings.Contains(got, "c") ||
		!strings.Contains(got, "d") || !strings.Contains(got, "e") || !strings.Contains(got, "f") {
		t.Errorf("SafeText lost visible text: %q", got)
	}
}

func TestSafeTextLeavesPlainUnicodeAlone(t *testing.T) {
	const text = "管理員 /etc/passwd · ok"
	if got := SafeText(text); got != text {
		t.Errorf("SafeText changed plain text: %q", got)
	}
}
