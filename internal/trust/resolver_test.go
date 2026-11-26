//go:build !windows

package trust

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeManager writes a dpkg shell script that answers for /owned and exits
// non-zero for everything else, the way dpkg -S does for an unlisted path. It
// reads every argument, so the same script answers the batch call.
func fakeManager(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		"rc=0\n" +
		"for p in \"$@\"; do\n" +
		"  case \"$p\" in -S) continue;; esac\n" +
		"  case \"$p\" in\n" +
		"    /owned*) echo \"pkg: $p\";;\n" +
		"    *) rc=1;;\n" +
		"  esac\n" +
		"done\n" +
		"exit $rc\n"
	path := filepath.Join(dir, "dpkg")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return dir
}

func TestResolverOwnedAndUnowned(t *testing.T) {
	fakeManager(t)
	resolver := NewResolver()
	if pkg, known := resolver.Owned("/owned"); pkg != "pkg" || !known {
		t.Errorf("Owned(/owned) = (%q, %v), want (pkg, true)", pkg, known)
	}
	if pkg, known := resolver.Owned("/unowned"); pkg != "" || !known {
		t.Errorf("Owned(/unowned) = (%q, %v), want (\"\", true)", pkg, known)
	}
	// a repeated query is a cache hit and answers the same
	if pkg, known := resolver.Owned("/unowned"); pkg != "" || !known {
		t.Errorf("cached Owned(/unowned) = (%q, %v)", pkg, known)
	}
}

func TestResolverOwnedAll(t *testing.T) {
	fakeManager(t)
	resolver := NewResolver()
	resolver.OwnedAll([]string{"/owned", "/unowned", "/owned-two", "/unowned"})
	for path, want := range map[string]string{
		"/owned":     "pkg",
		"/owned-two": "pkg",
		"/unowned":   "",
	} {
		pkg, known := resolver.Owned(path)
		if pkg != want || !known {
			t.Errorf("after the batch, Owned(%q) = (%q, %v), want (%q, true)", path, pkg, known, want)
		}
	}
}

func TestResolverWithoutManager(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	resolver := NewResolver()
	if pkg, known := resolver.Owned("/owned"); pkg != "" || known {
		t.Errorf("no manager must answer unknown, got (%q, %v)", pkg, known)
	}
}

func TestDpkgAnswer(t *testing.T) {
	cases := []struct {
		in     string
		pkg    string
		shared bool
	}{
		{"pkg: /x\n", "pkg", false},
		{"pkg:amd64: /x\n", "pkg", false},
		{"pkg, other: /usr/bin\n", "pkg", true},
		{"local diversion from: /x\n", "", false},
		{"pkg\n", "pkg", false},
	}
	for _, c := range cases {
		got := dpkgAnswer(c.in)
		if got.pkg != c.pkg || got.shared != c.shared {
			t.Errorf("dpkgAnswer(%q) = %+v, want pkg=%q shared=%t", c.in, got, c.pkg, c.shared)
		}
	}
}

func TestDpkgBatchDirectoryAndDiversion(t *testing.T) {
	dir := t.TempDir()
	script := `#!/bin/sh
rc=1
for p in "$@"; do
  case "$p" in
    -S) continue;;
    /dir) echo "pkg, other: /dir"; rc=0;;
    /diverted)
      echo "local diversion from: /diverted"
      echo "local diversion to: /diverted.REAL"
      rc=0;;
  esac
done
exit $rc
`
	binary := filepath.Join(dir, "dpkg")
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	resolver := &Resolver{dpkg: binary, cache: map[string]answer{}}
	answers := resolver.dpkgBatch([]string{"/dir", "/diverted"})
	if got := answers["/dir"]; got.pkg != "pkg" || !got.known || !got.shared {
		t.Errorf("directory row = %+v, want the first package and shared", got)
	}
	if got := answers["/diverted"]; got.pkg != "" || !got.known {
		t.Errorf("diversion row = %+v, want a known local file", got)
	}
}
