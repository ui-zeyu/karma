// tests for the home-glob expansion the authorized-keys tier takes from the check.

package native

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// expandHomes reads a container glob the way the shell's pathname expansion does:
// immediate child directories only, dot entries and plain files out; a bare path
// is one home; an entry that does not resolve contributes nothing.
func TestExpandHomes(t *testing.T) {
	container := t.TempDir()
	for _, name := range []string{"alice", "bob", ".cache"} {
		if err := os.Mkdir(filepath.Join(container, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(container, "README"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	solo := filepath.Join(t.TempDir(), "solo")
	if err := os.Mkdir(solo, 0o755); err != nil {
		t.Fatal(err)
	}

	got := expandHomes([]string{solo, container + "/*", filepath.Join(container, "gone")})
	want := []string{solo, filepath.Join(container, "alice"), filepath.Join(container, "bob")}
	if !slices.Equal(got, want) {
		t.Fatalf("expandHomes = %q, want %q", got, want)
	}
}
