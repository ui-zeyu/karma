// Tests for the section-shaped file read: one "== path" section per existing
// regular file, the tail window, and the missing-file guard.

package localfs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"karma/internal/section"
)

func TestReadSectionsSkipsMissingAndTails(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present.conf")
	missing := filepath.Join(dir, "missing.conf")
	if err := os.WriteFile(present, []byte("l1\nl2\nl3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// the glob stays literal on no match and is dropped by the [ -f ] guard
	got := ReadSections([]string{present, missing, dir + "/*.none"}, nil)
	want := "== " + present + "\nl1\nl2\nl3\n"
	if got != want {
		t.Fatalf("ReadSections body mismatch:\ngot  %q\nwant %q", got, want)
	}
	tailed := ReadSections([]string{present}, TailLines(2))
	if !strings.HasSuffix(tailed, "l2\nl3\n") || strings.Contains(tailed, "l1") {
		t.Fatalf("TailLines(2) kept the wrong window: %q", tailed)
	}
}

// TailLines is the in-process form of the tail tier's `tail -n N`, so the two
// must keep the same bytes: a body with or without its trailing newline, blank
// lines, and a window wider than the body.
func TestTailLinesMatchesTail(t *testing.T) {
	if _, err := exec.LookPath("tail"); err != nil {
		t.Skip("no tail, skipping the comparison")
	}
	bodies := []string{"l1\nl2\nl3\n", "l1\nl2\nl3", "", "\n", "\n\n", "one\n", "a\n\nb\n\n"}
	for _, body := range bodies {
		path := filepath.Join(t.TempDir(), "body")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, n := range []int{1, 2, 3, 10} {
			out, err := exec.Command("tail", "-n", strconv.Itoa(n), path).Output()
			if err != nil {
				t.Fatalf("tail -n %d: %v", n, err)
			}
			if got := TailLines(n)(body); got != string(out) {
				t.Errorf("TailLines(%d)(%q) = %q, tail keeps %q", n, body, got, out)
			}
		}
	}
}

// Cat is the reader form: the file's bytes, no section header.
func TestCatReadsTheFileAsItIs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "one")
	if err := os.WriteFile(path, []byte("a\nb\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Cat(path)
	if err != nil || string(got) != "a\nb\n" {
		t.Fatalf("Cat = %q, %v", got, err)
	}
	if _, err := Cat(filepath.Join(t.TempDir(), "gone")); err == nil {
		t.Fatal("a missing file should surface its error")
	}
}

// ReadSections prints one section per existing regular file, in word order with
// the globs' results sorted: a path that is gone and a path that is a directory
// print nothing, a glob expands the way the shell expands it, and a body whose
// last line carries no newline is closed with one — without the terminator the
// next "== path" header would glue onto that line.
func TestReadSectionsPrintsOneSectionPerFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	a := write("a.txt", "alpha\n")
	b := write("b.txt", "")
	c := write("c.txt", "x\ny\n")
	e := write("e.txt", "unterminated") // no terminator of its own
	nested := filepath.Join(dir, "sub")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	write("sub/d.txt", "deep\n")

	// A literal path that is gone, a literal that is a directory (dropped), the
	// same file again through the glob — a word list repeats what it repeats —
	// and the glob itself.
	patterns := []string{a, filepath.Join(dir, "gone.txt"), nested, dir + "/*.txt"}
	want := section.Line(a) + "alpha\n" +
		section.Line(a) + "alpha\n" +
		section.Line(b) +
		section.Line(c) + "x\ny\n" +
		section.Line(e) + "unterminated\n"
	if got := ReadSections(patterns, nil); got != want {
		t.Fatalf("ReadSections body mismatch:\ngot  %q\nwant %q", got, want)
	}
}

// The tail tier keeps the last n lines of each file and closes the section the
// same way: a file whose last line carries no newline keeps none here either,
// and the section's terminator is what the reader supplies.
func TestTailSectionsKeepTheLastLines(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	a := write("a.txt", "alpha\n")
	unterminated := write("unterminated.txt", "one\ntwo\nthree")
	empty := write("empty.txt", "")
	paths := []string{a, unterminated, empty}

	cases := []struct {
		n    int
		want [3]string
	}{
		{1, [3]string{"alpha\n", "three\n", ""}},
		{2, [3]string{"alpha\n", "two\nthree\n", ""}},
		{3, [3]string{"alpha\n", "one\ntwo\nthree\n", ""}},
		{400, [3]string{"alpha\n", "one\ntwo\nthree\n", ""}},
	}
	for _, c := range cases {
		want := section.Line(a) + c.want[0] + section.Line(unterminated) + c.want[1] + section.Line(empty) + c.want[2]
		if got := ReadSections(paths, TailLines(c.n)); got != want {
			t.Errorf("at n=%d:\ngot  %q\nwant %q", c.n, got, want)
		}
	}
}
