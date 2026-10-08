// Tests for the in-process file read: the list a file-list tier answers with,
// one file's body, the tail window, and the missing-file guard.

package localfs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestListFilesSkipsMissingAndReadBodyTails(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present.conf")
	missing := filepath.Join(dir, "missing.conf")
	if err := os.WriteFile(present, []byte("l1\nl2\nl3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// the glob stays literal on no match and is dropped by the [ -f ] guard
	if got, want := ListFiles([]string{present, missing, dir + "/*.none"}), present; got != want {
		t.Fatalf("ListFiles = %q, want %q", got, want)
	}
	if got, want := ReadBody(present, nil), "l1\nl2\nl3\n"; got != want {
		t.Fatalf("ReadBody = %q, want %q", got, want)
	}
	tailed := ReadBody(present, TailLines(2))
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

// ListFiles names one path per existing regular file, in word order with the
// globs' results sorted: a path that is gone and a path that is a directory name
// nothing, and a word list repeats what it repeats.
func TestListFilesNamesOnePathPerFile(t *testing.T) {
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
	want := strings.Join([]string{a, a, b, c, e}, "\n")
	if got := ListFiles(patterns); got != want {
		t.Fatalf("ListFiles mismatch:\ngot  %q\nwant %q", got, want)
	}
	// Each path's body is the file as it stands: a body whose last line carries
	// no newline keeps none here either, and the runner supplies the section's
	// terminator.
	if got := ReadBody(e, nil); got != "unterminated" {
		t.Fatalf("ReadBody(unterminated) = %q", got)
	}
	if got := ReadBody(b, nil); got != "" {
		t.Fatalf("ReadBody(empty) = %q", got)
	}
	if got := ReadBody(filepath.Join(dir, "gone.txt"), nil); got != "" {
		t.Fatalf("a missing file reads as empty, got %q", got)
	}
}

// The tail window is per file, so a file-list tier of tail reads keeps the last
// lines of each one.
func TestReadBodyKeepsTheTailWindow(t *testing.T) {
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

	cases := []struct {
		n    int
		want [3]string
	}{
		{1, [3]string{"alpha\n", "three", ""}},
		{2, [3]string{"alpha\n", "two\nthree", ""}},
		{3, [3]string{"alpha\n", "one\ntwo\nthree", ""}},
		{400, [3]string{"alpha\n", "one\ntwo\nthree", ""}},
	}
	for _, c := range cases {
		got := []string{
			ReadBody(a, TailLines(c.n)),
			ReadBody(unterminated, TailLines(c.n)),
			ReadBody(empty, TailLines(c.n)),
		}
		for index, want := range c.want {
			if got[index] != want {
				t.Errorf("at n=%d, file %d: got %q, want %q", c.n, index, got[index], want)
			}
		}
	}
}
