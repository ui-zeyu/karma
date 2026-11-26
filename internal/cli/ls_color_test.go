package cli

import (
	"strings"
	"testing"

	chrome "karma/internal/panel"
)

// TestLsRowPaintKeepsTheText pins the listing heuristic: the painted row
// still reads as the same bytes (ANSI takes no column), plain output is
// untouched, and the kind/permission hues land where the old listing put them.
func TestLsRowPaintKeepsTheText(t *testing.T) {
	row := "-rw-r--r--  1 root wheel    206 Nov 26 13:06 /etc/hosts"
	if got := lsRow(false, row); got != row {
		t.Fatalf("color off changed the row: %q", got)
	}
	painted := lsRow(true, row)
	if plain := chrome.StripANSI(painted); plain != row {
		t.Fatalf("painted row reads %q, want %q", plain, row)
	}
	if !strings.Contains(painted, chrome.Fg(2)) {
		t.Errorf("the read bit is not green: %q", painted)
	}
	if !strings.Contains(painted, chrome.Fg(247)) {
		t.Errorf("the size is not grey: %q", painted)
	}

	link := "lrwxrwxrwx  1 root root 7 Nov 26 13:06 /etc/link -> ../target"
	if plain := chrome.StripANSI(lsRow(true, link)); plain != link {
		t.Fatalf("symlink row reads %q, want %q", plain, link)
	}
	dir := "drwxr-xr-x  3 root wheel 96 Nov 19 18:02 /etc/manpaths.d"
	if !strings.Contains(lsRow(true, dir), chrome.Fg(4)) {
		t.Errorf("the directory name is not blue: %q", lsRow(true, dir))
	}
	if header := "== /etc"; lsRow(true, header) != header {
		t.Errorf("a section header must pass through: %q", lsRow(true, header))
	}
}
