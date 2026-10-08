package section

import "testing"

// Line renders the header the report prints above a section: the marker, the
// title as it stands, then the newline.
func TestLineRendersTheMarkerAndTitle(t *testing.T) {
	if got, want := Line("/etc/passwd"), "== /etc/passwd\n"; got != want {
		t.Errorf("Line = %q, want %q", got, want)
	}
}

// A title is the rest of the line as it stands, trailing space included: the
// producer wrote it, and a reader that wants it trimmed says so itself.
func TestTitleReadsTheRestOfTheLine(t *testing.T) {
	title, ok := Title("== crontab -l ")
	if !ok || title != "crontab -l " {
		t.Errorf("Title = %q, %v; want %q, true", title, ok, "crontab -l ")
	}
}

// A body line opens nothing: the marker is the header, not a word in the text.
func TestTitleRefusesABodyLine(t *testing.T) {
	for _, line := range []string{"crontab -l", "==crontab", "", "  == x"} {
		if title, ok := Title(line); ok {
			t.Errorf("Title(%q) = %q, true; want false", line, title)
		}
	}
}
