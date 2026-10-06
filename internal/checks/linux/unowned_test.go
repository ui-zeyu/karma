// The unowned-file check ships one shell pipeline and one in-process tier, and
// the two have to print the same text: these tests run the pipeline the ssh
// channel runs against a fixture with a fake package manager and require it to
// agree, row for row, with the local tier's own answer.

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
	"karma/internal/reader"
	"karma/internal/script"
	"karma/internal/testkit"
)

// fakeManager writes one package manager into a directory of its own and
// returns a PATH with that directory in front.
func fakeManager(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir + ":" + os.Getenv("PATH")
}

// unownedFixture is one system directory: three files the fake package manager
// will not list, one it will, and an update-alternatives link neither side
// reports. The canonical path is returned, because both tiers resolve the
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

// The dpkg branch: the pipeline searches with one wildcard pattern per
// directory and the fake answers as dpkg does, so a pattern that does not reach
// the manager leaves every file looking unowned and the expectation fails.
func TestUnownedScriptAndNativeAgreeOnDpkg(t *testing.T) {
	requireSh(t, "sh", "awk", "sed", "find", "readlink", "sort")
	root := unownedFixture(t)
	path := fakeManager(t, "dpkg", fakeOwns(`*evil*|*/-t|*/.hidden`))
	t.Setenv("PATH", path)

	want := strings.Join([]string{root + "/-t", root + "/.hidden", root + "/evil.so"}, "\n") + "\n"
	if got := runVerifyScript(t, script.UnownedScript([]string{root}), []string{"PATH=" + path}); got != want {
		t.Errorf("the pipeline reported\n%q\nwant\n%q", got, want)
	}
	if got := unownedNative(t, root); got != want {
		t.Errorf("the local tier reported\n%q\nwant\n%q", got, want)
	}
}

// The rpm branch: the manager prints every file it ships, in one list, and the
// same comparison runs over it.
func TestUnownedScriptAndNativeAgreeOnRpm(t *testing.T) {
	requireSh(t, "sh", "awk", "sed", "find", "readlink", "sort")
	root := unownedFixture(t)
	path := fakeManager(t, "rpm", `for f in `+strings.Join([]string{
		root + "/keep", root + "/link",
	}, " ")+`; do
  echo "$f"
done
`)
	t.Setenv("PATH", path)

	want := strings.Join([]string{root + "/-t", root + "/.hidden", root + "/evil.so"}, "\n") + "\n"
	if got := runVerifyScript(t, script.UnownedScript([]string{root}), []string{"PATH=" + path}); got != want {
		t.Errorf("the pipeline reported\n%q\nwant\n%q", got, want)
	}
	if got := unownedNative(t, root); got != want {
		t.Errorf("the local tier reported\n%q\nwant\n%q", got, want)
	}
}

// A host with neither package manager answers 127, which the chain reads as
// "no answer here" rather than an empty database.
func TestUnownedScriptWithoutAPackageManagerExits127(t *testing.T) {
	requireSh(t, "sh")
	dir := t.TempDir()
	cmd := exec.Command("/bin/sh", "-c", script.UnownedScript([]string{dir}))
	cmd.Env = []string{"PATH=" + t.TempDir()}
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 127 {
		t.Fatalf("a host without a package manager exited with %v, want 127", err)
	}
}

// A directory whose every file the database lists renders nothing: the check's
// answer is the rows, and an empty body is a complete one.
func TestUnownedBodyEmptyWhenEverythingIsOwned(t *testing.T) {
	root := unownedFixture(t)
	path := fakeManager(t, "dpkg", fakeOwns(""))
	t.Setenv("PATH", path)
	if got := unownedNative(t, root); got != "" {
		t.Errorf("a directory the database covers rendered %q, want nothing", got)
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
		document := reader.Analyze(tc.text, check.Rules, check.Filters, check.Normalize, 0)
		line := document.Sections[0].Lines[0]
		if line.Severity != tc.severity {
			t.Errorf("%q should be graded %v, got %v", tc.text, tc.severity, line.Severity)
		}
		if hits := testkit.HitIDs(t, tc.text, check); !slices.Contains(hits, tc.rule) {
			t.Errorf("%q should light %s, got %v", tc.text, tc.rule, hits)
		}
	}
}

// unownedNative runs the local tier over one directory with the PATH the test
// set, so the fake package manager answers it too.
func unownedNative(t *testing.T, dir string) string {
	t.Helper()
	body, err := native.UnownedFiles([]string{dir})(context.Background())
	if err != nil {
		t.Fatalf("the local tier failed: %v", err)
	}
	return body
}
