// Tests for the listing tier and its reader form: Ls is the rows the panels
// show, with the columns lined up.

package localfs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Ls is the reader form of the listing rows: bare ls-l bodies (no epoch
// prefix), the same mtime-descending order, no cap, dot entries included, and
// a file operand prints its own row. A path list prints one section per path;
// a failed path leaves the others printed and its error with the caller.
func TestLsRowsAndFileOperand(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "old")
	fresh := filepath.Join(dir, "fresh")
	writeTouched(t, old, time.Now().Add(-48*time.Hour))
	writeTouched(t, fresh, time.Now())

	got, err := Ls([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("wanted two rows, got %q", got)
	}
	// a single path prints bare rows: mtime descending, no epoch prefix, no
	// section header
	if !strings.HasSuffix(lines[0], " "+fresh) {
		t.Fatalf("the fresh entry should lead: %q", lines)
	}
	if !strings.HasSuffix(lines[1], " "+old) {
		t.Fatalf("the old entry should follow: %q", lines)
	}
	// the rows are listingRows with the epoch prefix cut off, not a second listing
	// (the columns are padded for display, so compare the fields)
	collected, err := listingRows(dir, 0, NewNameCache())
	if err != nil {
		t.Fatal(err)
	}
	if len(collected) != len(lines) {
		t.Fatalf("Ls and listingRows diverged: %q vs %q", lines, collected)
	}
	for i, line := range lines {
		if fields := strings.SplitN(line, " ", 9); len(fields) == 9 {
			line = strings.Join(fields[:8], " ") + " " + fields[8]
		}
		want := rowBody(collected[i])
		if line != want {
			t.Fatalf("Ls row %d is not the panel body:\n got %q\nwant %q", i, line, want)
		}
	}

	// a file operand prints its own row; a symlink operand keeps the link row
	row, err := Ls([]string{fresh})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(row, "-rw") || !strings.HasSuffix(strings.TrimSuffix(row, "\n"), " "+fresh) {
		t.Fatalf("a file operand should print its own row: %q", row)
	}
	link := filepath.Join(dir, "alias")
	if err := os.Symlink("fresh", link); err != nil {
		t.Skipf("symlinks are unavailable here: %v", err)
	}
	if row, err = Ls([]string{link}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(row, "l") || !strings.HasSuffix(strings.TrimSuffix(row, "\n"), "alias -> fresh") {
		t.Fatalf("a symlink operand should keep the link row: %q", row)
	}

	// a dot entry shows like find lists it
	hidden := filepath.Join(dir, ".env")
	writeTouched(t, hidden, time.Now().Add(-1*time.Hour))
	if got, err = Ls([]string{dir}); err != nil || !strings.Contains(got, hidden) {
		t.Fatalf("dot entries belong in the listing: %q (%v)", got, err)
	}

	// several paths print one section per path, the collection sections'
	// own header; a failed path keeps its section out while the rest print
	other := t.TempDir()
	otherFile := filepath.Join(other, "side")
	writeTouched(t, otherFile, time.Now())
	got, err = Ls([]string{dir, filepath.Join(dir, "missing"), other})
	if err == nil {
		t.Fatal("the missing path should surface its error")
	}
	if !strings.Contains(got, "== "+dir+"\n") || !strings.Contains(got, "== "+other+"\n") {
		t.Fatalf("each surviving path should head its own section: %q", got)
	}
	if !strings.Contains(got, " "+otherFile) || strings.Contains(got, "missing") {
		t.Fatalf("the good sections should print and only those: %q", got)
	}
}

// A listing's columns line up like ls -l: the date of every row starts in the
// same column even when sizes and link counts differ.
func TestLsColumnsAlign(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "tiny")
	large := filepath.Join(dir, "huge")
	if err := os.WriteFile(small, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(large, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	// one extra name: the two rows then differ in link count as well
	if err := os.Link(large, filepath.Join(dir, "huge2")); err != nil {
		t.Skipf("hard links are unavailable here: %v", err)
	}

	got, err := Ls([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("wanted several rows, got %q", got)
	}
	// every row's first eight columns occupy the same width, so the path starts
	// at one column whatever the link count and size are
	pathAt := -1
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 9 {
			t.Fatalf("row does not hold the ls -l fields: %q", line)
		}
		// the path is the row's tail: what follows the last column separator,
		// after the padding that lines the earlier columns up
		at := strings.LastIndex(line, " "+fields[8])
		if pathAt < 0 {
			pathAt = at
		} else if at != pathAt {
			t.Fatalf("the path column moved: %d vs %d\n%s", at, pathAt, got)
		}
		// the padding sits between the columns, never inside the path
		if !filepath.IsAbs(fields[8]) {
			t.Fatalf("the path should be untouched: %q", line)
		}
	}
}
