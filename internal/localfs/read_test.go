// Tests for the section-shaped file read: one "== path" section per existing
// regular file, the tail window, and the missing-file guard.

package localfs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
