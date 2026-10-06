// The package-verify tier on the ssh and ttyd channels is one shell pipeline
// over the target's own file(1) and ls -l: the tags, sed, the awk pass and the
// file/ls calls are a contract with the shell rather than with Go. These tests
// run that pipeline against a fixture the way the remote channel runs it, so a
// broken tag or a mistyped field fails here instead of reporting a wall of
// rows on a target.

package linux

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeVerifier writes the `dpkg` the pipeline calls, printing body on stdout,
// and returns a PATH with it in front.
func fakeVerifier(t *testing.T, body string) []string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dpkg"), []byte("#!/bin/sh\ncat <<'KARMA'\n"+body+"KARMA\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "PATH=") {
			env = append(env, kv)
		}
	}
	return append(env, "PATH="+dir+":"+os.Getenv("PATH"))
}

// runVerifyScript runs the tier's script under /bin/sh with the fake verifier
// in front of PATH.
func runVerifyScript(t *testing.T, script string, env []string) string {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("the tier script failed: %v (output %q)", err, out)
	}
	return string(out)
}

// A divergence that is mostly text is counted per directory, while the file
// that could be a finding — an executable here — is named with its type and
// attributes, and a small directory keeps its names.
func TestVerifyScriptNamesProgramsAndCountsTheRest(t *testing.T) {
	requireSh(t, "sh", "awk", "sed", "file", "ls", "sort", "uniq")
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
	out := runVerifyScript(t, verifyScript("dpkg -V"), fakeVerifier(t, body.String()))

	for _, want := range []string{
		"== executables, libraries and conffiles\n??5??????   " + tool + "\n",
		"== file\n" + tool + ": ",
		"== ls\n",
		"== other changed files (grouped by directory)\n??5??????   " + readme + "\n",
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
func TestVerifyScriptStaysSilentWhenNothingDiffers(t *testing.T) {
	requireSh(t, "sh", "awk", "sed", "file", "ls")
	if out := runVerifyScript(t, verifyScript("dpkg -V"), fakeVerifier(t, "")); out != "" {
		t.Errorf("a clean verification printed %q, want nothing", out)
	}
}

// A target without the package manager answers 127 from the tier itself: the
// chain reads that as "no answer here" and falls to the next package manager.
func TestVerifyScriptWithoutTheVerifierExits127(t *testing.T) {
	requireSh(t, "sh")
	env := []string{"PATH=" + t.TempDir()}
	cmd := exec.Command("/bin/sh", "-c", verifyScript("dpkg -V"))
	cmd.Env = env
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 127 {
		t.Fatalf("a host without dpkg exited with %v, want 127", err)
	}
}
