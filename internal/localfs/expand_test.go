// Tests for the path word lists: the shell's glob rule (dot names only when the
// pattern spells the dot) and the [ -f ] / [ -d ] guards behind it.

package localfs

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// shellGlob must not hand back dot-file names the shell's own glob would skip:
// /etc/cron.d/* has a .placeholder the sh source never sees.
func TestShellGlobSkipsDotFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"job", ".placeholder", ".hidden"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := shellGlob(filepath.Join(dir, "*"))
	if len(got) != 1 || filepath.Base(got[0]) != "job" {
		t.Errorf("glob * = %v, want just the plain name", got)
	}
	got = shellGlob(filepath.Join(dir, ".*"))
	if len(got) != 2 {
		t.Errorf("glob .* = %v, want both dot names", got)
	}
	if got = shellGlob(filepath.Join(dir, "*.nomatch")); len(got) != 0 {
		t.Errorf("non-matching glob = %v, want nothing", got)
	}
}

// ExpandFiles keeps the existing regular files, in word-list order with each
// glob's results sorted; a bare path that is not a regular file is dropped, the
// way the sh source's `[ -f "$f" ]` guard drops it.
func TestExpandFilesKeepsRegularFilesOnly(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.conf", "b.conf", ".hidden"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	got := ExpandFiles([]string{filepath.Join(dir, "*.conf"), sub, filepath.Join(dir, "gone")})
	want := []string{filepath.Join(dir, "a.conf"), filepath.Join(dir, "b.conf")}
	if !slices.Equal(got, want) {
		t.Fatalf("ExpandFiles = %q, want %q", got, want)
	}
}

// ExpandDirs substitutes $(uname -r) the way the target shell does, keeps only
// the directories a glob names, and passes a bare path through so its (empty)
// section is still emitted.
func TestExpandDirsSubstitutesAndKeepsDirectories(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "mod"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The release is whatever this host reports (empty off Linux); the
	// assertion is that the substitution ran, not what it produced.
	release, _ := KernelRelease()
	got := ExpandDirs([]string{dir + "/*", "/lib/modules/$(uname -r)", filepath.Join(dir, "gone")})
	want := []string{filepath.Join(dir, "mod"), "/lib/modules/" + release, filepath.Join(dir, "gone")}
	if !slices.Equal(got, want) {
		t.Fatalf("ExpandDirs = %q, want %q", got, want)
	}
}
