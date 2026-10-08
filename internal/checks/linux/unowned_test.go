// The unowned-file tier reads the directory level in process and asks the
// package database which of those paths it knows: these tests run it against a
// fixture with a fake package manager on PATH, so a query that misses a
// directory spelling, an owned path that reads as unowned, or a link the tier
// was supposed to leave alone fails here.

package linux

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"karma/internal/checks/linux/native"
	"karma/internal/model"
	"karma/internal/testkit"
)

// managerFixture writes one package manager into a directory of its own, links
// the tools its own body calls beside it, and returns that directory as the
// whole PATH. The closed PATH is what makes the branch a test names the branch
// the tier takes: the tier asks `command -v dpkg` first, so on a host that has
// dpkg installed — Debian, Ubuntu — an open PATH answers through the host's own
// dpkg and the rpm case never runs.
func managerFixture(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	for _, tool := range []string{"cat", "find", "sed"} {
		path, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("no %s on this host", tool)
		}
		if err := os.Symlink(path, filepath.Join(dir, tool)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// unownedFixture is one system directory: three files the fake package manager
// will not list, one it will, and an update-alternatives link the tier reports
// for no one. The canonical path is returned, because the tier resolves the
// directory before reading it (on macOS the temp root itself is a symlink).
func unownedFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"keep", "evil.so", "-t", ".hidden"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/etc/alternatives/awk", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

// fakeOwns is the body of a fake dpkg: for every pattern it is handed it lists
// the directory the pattern names and reports one row per entry, names matched
// by skip left out. It walks with find rather than a shell glob, because a glob
// would never reach the dotfiles the fixture is built around.
func fakeOwns(skip string) string {
	body := `for p in "$@"; do
  d=${p%/*}
  for f in $(LC_ALL=C find "$d" -maxdepth 1 -mindepth 1 2>/dev/null); do
`
	if skip != "" {
		body += "    case \"$f\" in " + skip + ") continue;; esac\n"
	}
	return body + `    echo "pkg: $f"
  done
done
`
}

// The dpkg branch: the tier searches with one wildcard pattern per directory
// and the fake answers as dpkg does, so a pattern that does not reach the
// manager leaves every file looking unowned and the expectation fails.
func TestUnownedFilesReadsTheDpkgDatabase(t *testing.T) {
	root := unownedFixture(t)
	t.Setenv("PATH", managerFixture(t, "dpkg", fakeOwns(`*evil*|*/-t|*/.hidden`)))

	want := strings.Join([]string{root + "/-t", root + "/.hidden", root + "/evil.so"}, "\n") + "\n"
	if got := unownedNative(t, root); got != want {
		t.Errorf("the tier reported\n%q\nwant\n%q", got, want)
	}
}

// The rpm branch: the manager prints every file it ships, in one list, and the
// same comparison runs over it.
func TestUnownedFilesReadsTheRpmDatabase(t *testing.T) {
	root := unownedFixture(t)
	t.Setenv("PATH", managerFixture(t, "rpm", `for f in `+strings.Join([]string{
		root + "/keep", root + "/link",
	}, " ")+`; do
  echo "$f"
done
`))

	want := strings.Join([]string{root + "/-t", root + "/.hidden", root + "/evil.so"}, "\n") + "\n"
	if got := unownedNative(t, root); got != want {
		t.Errorf("the tier reported\n%q\nwant\n%q", got, want)
	}
}

// A host with neither package manager has no database to compare against,
// which is the tier's "no answer here" rather than an empty answer.
func TestUnownedFilesWithoutAPackageManagerIsUnavailable(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	body, err := native.UnownedFiles([]string{t.TempDir()})(context.Background())
	if !errors.Is(err, model.ErrTierUnavailable) {
		t.Fatalf("a host without a package manager should be unavailable, got %q / %v", body, err)
	}
}

// A directory whose every file the database lists renders nothing: the check's
// answer is the rows, and an empty body is a complete one.
func TestUnownedBodyEmptyWhenEverythingIsOwned(t *testing.T) {
	root := unownedFixture(t)
	t.Setenv("PATH", managerFixture(t, "dpkg", fakeOwns("")))
	if got := unownedNative(t, root); got != "" {
		t.Errorf("a directory the database covers rendered %q, want nothing", got)
	}
}

// The usrmerge case the lab showed: dpkg's database records the pre-merge
// spelling (/bin/bash) while the directory the walk reads is the canonical one
// (/usr/bin), so a query that only knows the canonical spelling calls half of
// /usr/bin unowned. The fake dpkg answers only the legacy spelling — the shape
// dpkg 1.21's database has — and the tier must still agree that the listed file
// is owned and only the stranger is not.
func TestUnownedFilesFollowsAUsrmergeAlias(t *testing.T) {
	base := t.TempDir()
	merged := filepath.Join(base, "usr", "bin")
	if err := os.MkdirAll(merged, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"kept", "evil.so"} {
		if err := os.WriteFile(filepath.Join(merged, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	legacy := filepath.Join(base, "bin")
	if err := os.Symlink("usr/bin", legacy); err != nil {
		t.Fatal(err)
	}
	// dpkg answers only the /bin spelling, the way its pre-merge database does.
	dpkg := "#!/bin/sh\nfor p in \"$@\"; do\n  case \"$p\" in \"" + legacy + "/*\") echo \"pkg: $p\" | sed 's|\\*|kept|';; esac\ndone\n"
	t.Setenv("PATH", managerFixture(t, "dpkg", dpkg))

	resolved, err := filepath.EvalSymlinks(merged)
	if err != nil {
		t.Fatal(err)
	}
	want := resolved + "/evil.so\n"
	if got := unownedNative(t, merged, legacy); got != want {
		t.Errorf("the tier reported\n%q\nwant\n%q", got, want)
	}
}

// The two row classes the panel grades: a file outside the database is the
// finding, and the hidden and dash-led names among them are painted by the
// rules that name those shapes.
func TestUnownedFileGrades(t *testing.T) {
	check := testkit.CheckByID(t, All, "unowned-files")
	cases := []struct {
		text     string
		severity model.Severity
		rule     string
	}{
		{`/usr/lib/inject.so`, model.High, "unowned-file"},
		{`/bin/-t`, model.High, "unowned-file"},
		{`/usr/lib/.inject.so`, model.High, "unowned-file"},
	}
	for _, tc := range cases {
		document := testkit.Analyze(tc.text, check)
		line := document.Sections[0].Lines[0]
		if line.Severity != tc.severity {
			t.Errorf("%q should be graded %v, got %v", tc.text, tc.severity, line.Severity)
		}
		if hits := testkit.HitIDs(t, tc.text, check); !slices.Contains(hits, tc.rule) {
			t.Errorf("%q should light %s, got %v", tc.text, tc.rule, hits)
		}
	}
}

// unownedNative runs the tier over the directories with the PATH the test set,
// so the fake package manager answers it too.
func unownedNative(t *testing.T, dirs ...string) string {
	t.Helper()
	body, err := native.UnownedFiles(dirs)(context.Background())
	if err != nil {
		t.Fatalf("the tier failed: %v", err)
	}
	return body
}
