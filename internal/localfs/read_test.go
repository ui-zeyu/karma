// Tests for the section-shaped file read: one "== path" section per existing
// regular file, the tail window, and the missing-file guard.

package localfs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"karma/internal/script"
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

// The section loop runs twice — this package's in-process read and the
// collection script's `for f in ...; do [ -f "$f" ] && { echo "== $f"; cat; }`
// — and the two are the same tier of dozens of checks. One directory of
// fixtures, read both ways, must produce the same bytes.
func TestReadSectionsMatchesTheShellLoop(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh, skipping the script comparison")
	}
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	write("a.txt", "alpha\n")
	write("b.txt", "")
	write("c.txt", "x\ny\n")
	nested := filepath.Join(dir, "sub")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	write("sub/d.txt", "deep\n")

	// A literal path that is gone, a literal that is a directory (the [ -f ]
	// guard drops both), a repeated path, and a glob behind it.
	patterns := []string{
		filepath.Join(dir, "a.txt"),
		filepath.Join(dir, "gone.txt"),
		nested,
		dir + "/*.txt",
	}
	command := exec.Command("sh", "-c", script.ReadFiles(patterns, `cat "$f"`, true))
	out, err := command.Output()
	if err != nil {
		t.Fatalf("the collection loop failed: %v\n%s", err, out)
	}
	got, want := ReadSections(patterns, nil), string(out)
	if got != want {
		t.Fatalf("the two section loops disagree:\nin-process %q\nshell      %q", got, want)
	}
}
