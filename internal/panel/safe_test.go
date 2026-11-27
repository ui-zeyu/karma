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

func TestEscapeScannerAgreesOnOSCSequences(t *testing.T) {
	link := "\x1b]8;;http://example.test\x1b\\link\x1b]8;;\x1b\\"
	if got := DisplayWidth(link); got != 4 {
		t.Errorf("width with an OSC hyperlink = %d, want 4", got)
	}
	if got := StripANSI(link); got != "link" {
		t.Errorf("stripped = %q, want link", got)
	}
	if got := SafeText(link); got != "link" {
		t.Errorf("safe = %q, want link", got)
	}
	if got := DisplayWidth("\x1b[31mpainted\x1b[0m"); got != 7 {
		t.Errorf("width with SGR = %d, want 7", got)
	}
	if got := DisplayWidth("trailing\x1b"); got != 8 {
		t.Errorf("width with a lone ESC = %d, want 8", got)
	}
}
