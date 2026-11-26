package cli

import (
	"strings"
	"testing"

	chrome "karma/internal/panel"
)

// TestHighlightContentKeepsTheBytes pins the content view's contract: the
// painted text reads as the same bytes, plain streams stay raw, and a binary
// or unrecognized file passes through.
func TestHighlightContentKeepsTheBytes(t *testing.T) {
	script := "#!/bin/bash\n# set up\nexport PATH=\"$HOME/bin:$PATH\"\ncd $HOME\nif [ -f x ]; then echo 'hi' # tail\nfi\n"
	painted := string(highlightContent("setup.sh", []byte(script), true))
	if plain := chrome.StripANSI(painted); plain != script {
		t.Fatalf("painted text reads %q, want %q", plain, script)
	}
	for _, want := range []string{
		chrome.Fg(chrome.MutedColor), // the comments
		chrome.Fg(5),                 // the keywords
		chrome.Fg(4),                 // the strings
		chrome.Fg(6),                 // the variables
	} {
		if !strings.Contains(painted, want) {
			t.Errorf("the script carries no %q hue", want)
		}
	}
	if raw := string(highlightContent("setup.sh", []byte(script), false)); raw != script {
		t.Fatalf("plain stream reads %q, want %q", raw, script)
	}
	binary := []byte("a\x00b")
	if got := string(highlightContent("x.sh", binary, true)); got != string(binary) {
		t.Fatalf("binary content was rewritten: %q", got)
	}
	unknown := "just words\n"
	if got := string(highlightContent("notes.txt", []byte(unknown), true)); got != unknown {
		t.Fatalf("an unknown format was rewritten: %q", got)
	}
}

// TestHighlightConfigFiles pins the ssh and key/value shapes.
func TestHighlightConfigFiles(t *testing.T) {
	sshd := "Port 22 # the door\n# a comment\n"
	painted := string(highlightContent("/etc/ssh/sshd_config", []byte(sshd), true))
	if plain := chrome.StripANSI(painted); plain != sshd {
		t.Fatalf("painted sshd config reads %q, want %q", plain, sshd)
	}
	if !strings.Contains(painted, chrome.Fg(5)) {
		t.Errorf("the directive carries no keyword hue")
	}

	unit := "[Unit]\nDescription=thing\n"
	painted = string(highlightContent("x.service", []byte(unit), true))
	if plain := chrome.StripANSI(painted); plain != unit {
		t.Fatalf("painted unit reads %q, want %q", plain, unit)
	}
	if !strings.Contains(painted, chrome.Fg(4)) {
		t.Errorf("the unit key carries no key hue")
	}
}
