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

func TestDpkgRow(t *testing.T) {
	cases := []struct{ in, want string }{
		{"pkg: /x\n", "pkg"},
		{"pkg:amd64: /x\n", "pkg"},
		{"pkg\n", "pkg"},
	}
	for _, c := range cases {
		if got := dpkgRow(c.in); got != c.want {
			t.Errorf("dpkgRow(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
