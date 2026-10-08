// The package-verify tier reads the verifier's own output in process and builds
// the body from the filesystem: the tags, the classification and the grouping are
// Go, so these tests run the tier over a fixture with the verifier stubbed on
// PATH, and a mistyped field or a lost row fails here instead of reporting a wall
// of rows on a target.

package linux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"karma/internal/checks/linux/native"
	"karma/internal/model"
)

// fakeVerifier writes the `dpkg` the tier calls, printing body on stdout, and
// puts it in front of PATH for the rest of the test.
func fakeVerifier(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dpkg"), []byte("#!/bin/sh\ncat <<'KARMA'\n"+body+"KARMA\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// verify runs the tier with dpkg first on PATH, the way a target with dpkg has it.
func verify(t *testing.T) string {
	t.Helper()
	out, err := native.PkgVerify([]string{"dpkg", "-V"})(context.Background())
	if err != nil {
		t.Fatalf("the tier failed: %v", err)
	}
	return out
}

// A divergence that is mostly text is counted per directory, while the file
// that could be a finding — an executable here — is named with its type and
// attributes, and a small directory keeps its names.
func TestVerifyNamesProgramsAndCountsTheRest(t *testing.T) {
	root := t.TempDir()
	prog := filepath.Join(root, "prog")
	mass := filepath.Join(root, "mass")
	if err := os.MkdirAll(prog, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(mass, 0o755); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(prog, "tool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	readme := filepath.Join(prog, "readme")
	if err := os.WriteFile(readme, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// One verifier line per row: the two existing files, then four rows whose
	// files are gone (dpkg's flag field cannot tell that apart by itself).
	rows := []string{tool, readme}
	for _, name := range []string{"a", "b", "c", "d"} {
		rows = append(rows, filepath.Join(mass, name))
	}
	var body strings.Builder
	for _, row := range rows {
		body.WriteString("??5??????   " + row + "\n")
	}
	fakeVerifier(t, body.String())

	out := verify(t)
	// The body is one section: the named rows, their type and attribute rows,
	// then the counted remainder, in that order.
	for _, want := range []string{
		"??5??????   " + tool + "\n",
		tool + ": ",
		readme + "\n",
		"??5??????   " + mass + "/  4 files missing\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the tier's output is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, mass+"/a") {
		t.Errorf("a counted directory still names its files:\n%s", out)
	}
}

// A clean verification is an empty answer: the check must not fall through to
// the other package manager's tier, and it must not print a header either.
func TestVerifyStaysSilentWhenNothingDiffers(t *testing.T) {
	fakeVerifier(t, "")
	if out := verify(t); out != "" {
		t.Errorf("a clean verification printed %q, want nothing", out)
	}
}

// A target without the package manager answers unavailable, which the chain
// reads as "no answer here" and falls to the next package manager.
func TestVerifyWithoutTheVerifierIsUnavailable(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	out, err := native.PkgVerify([]string{"dpkg", "-V"})(context.Background())
	if !errors.Is(err, model.ErrTierUnavailable) {
		t.Fatalf("a host without dpkg should be unavailable, got %q / %v", out, err)
	}
}
