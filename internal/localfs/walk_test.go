// Tests for the find and grep replacements: depth and -xdev semantics, prune,
// and grep -rnI's row shape.

package localfs

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestPathDepth(t *testing.T) {
	cases := []struct {
		root, path string
		want       int
	}{
		{"/", "/", 0},
		{"/", "/proc", 1},
		{"/", "/a/b", 2},
		{"/tmp", "/tmp", 0},
		{"/tmp", "/tmp/a", 1},
		{"/tmp", "/tmp/a/b", 2},
		{"/etc/skel/", "/etc/skel/x", 1},
	}
	for _, c := range cases {
		base := strings.TrimSuffix(c.root, "/")
		if base == "" {
			base = "/"
		}
		if got := pathDepth(base, c.path); got != c.want {
			t.Errorf("pathDepth(%s, %s) = %d, want %d", c.root, c.path, got, c.want)
		}
	}
}

func TestWalkTreeDepthAndPrune(t *testing.T) {
	dir := t.TempDir()
	deep := filepath.Join(dir, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var seen []string
	_ = WalkTree(context.Background(), dir, 2, false, nil, func(path string, info os.FileInfo) bool {
		seen = append(seen, path)
		return true
	})
	// depth 2 = root, a, b — the file at depth 3 and directory c stay out
	if slices.ContainsFunc(seen, func(p string) bool { return strings.HasSuffix(p, "/f") }) {
		t.Fatalf("depth cap did not stop the walk: %v", seen)
	}
	pruned := map[string]bool{filepath.Join(dir, "a"): true}
	seen = nil
	_ = WalkTree(context.Background(), dir, 0, false, func(path string, _ os.FileInfo) bool {
		return pruned[path]
	}, func(path string, info os.FileInfo) bool {
		seen = append(seen, path)
		return true
	})
	if slices.ContainsFunc(seen, func(p string) bool { return strings.HasSuffix(p, "b") }) {
		t.Fatalf("pruned directory was descended into: %v", seen)
	}
}

func TestGrepWalk(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		filepath.Join(dir, "a.php"):                  "<?php eval($_POST['x']); ?>\nclean\n",
		filepath.Join(dir, "b.txt"):                  "eval($_POST['x'])\n",
		filepath.Join(dir, "skip.php"):               "eval($_POST['x'])\nlater\x00nul\n",
		filepath.Join(sub, "c.php"):                  "line\n<?php eval($_REQUEST['y']);\n",
		filepath.Join(dir, "node_modules", "d.php"):  "eval($_POST['x'])\n",
		filepath.Join(dir, ".git", "e.php"):          "eval($_POST['x'])\n",
		filepath.Join(sub, "vendor", "keep.inc.php"): "",
	}
	for path, body := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	opt := GrepScan{
		Pattern:     regexp.MustCompile(`eval\(\$_(POST|REQUEST)`),
		Includes:    []string{"*.php"},
		ExcludeDirs: []string{".git", "node_modules"},
	}
	hits := GrepWalk(context.Background(), dir, opt)
	want := []string{
		filepath.Join(dir, "a.php") + ":1:",
		filepath.Join(sub, "c.php") + ":2:",
	}
	if len(hits) != len(want) {
		t.Fatalf("wanted %d hits, got %v", len(want), hits)
	}
	for i, prefix := range want {
		if !strings.HasPrefix(hits[i], prefix) {
			t.Fatalf("hit %d = %q, want prefix %q", i, hits[i], prefix)
		}
	}
}

// TestGrepWalkExcludes pins the scan's name rules: an exclude matches a basename
// at every depth, the include glob keeps one file class alone, and MaxHits caps
// the rows afterwards.
func TestGrepWalkExcludes(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "deep", "nested")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		filepath.Join(dir, "a.pth"):                        "import evil\n",
		filepath.Join(dir, "distutils-precedence.pth"):     "import legit\n",
		filepath.Join(nested, "_distutils_system_mod.pth"): "import legit\n",
		filepath.Join(nested, "b.pth"):                     "import evil\n",
		filepath.Join(dir, "notes.txt"):                    "import evil\n",
	}
	for path, body := range files {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	opt := GrepScan{
		Pattern:  regexp.MustCompile(`^import`),
		Includes: []string{"*.pth"},
		Excludes: []string{"distutils-precedence.pth", "_distutils_system_mod.pth"},
	}
	hits := GrepWalk(context.Background(), dir, opt)
	want := []string{
		filepath.Join(dir, "a.pth") + ":1:import evil",
		filepath.Join(nested, "b.pth") + ":1:import evil",
	}
	if !slices.Equal(hits, want) {
		t.Fatalf("hits = %v, want %v", hits, want)
	}
	opt.MaxHits = 1
	if capped := GrepWalk(context.Background(), dir, opt); !slices.Equal(capped, want[:1]) {
		t.Fatalf("capped hits = %v, want %v", capped, want[:1])
	}
}
