package section

import "testing"

// Line renders the header the report prints above a section: the marker, the
// title as it stands, then the newline.
func TestLineRendersTheMarkerAndTitle(t *testing.T) {
	if got, want := Line("/etc/passwd"), "== /etc/passwd\n"; got != want {
		t.Errorf("Line = %q, want %q", got, want)
	}
}
