//go:build unix

package linux

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// runScriptBounded runs one collection script through the target's own /bin/sh
// under a deadline: a script that parks in open(2) is killed here and the test
// fails, instead of spending a walk's budget on the target.
func runScriptBounded(t *testing.T, script string) string {
	t.Helper()
	requireSh(t, "sh", "awk", "sed", "find", "cat")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script)
	// A killed shell can leave a grandchild holding the output pipe: without a
	// wait delay this test would hang on that pipe instead of reporting the
	// regression it was written to catch.
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.Output()
	if ctx.Err() != nil {
		t.Fatalf("the script did not finish within 10s: a path it opened never answered\n%s", script)
	}
	if err != nil {
		t.Fatalf("the script failed: %v (output %q)", err, out)
	}
	return string(out)
}

func plantFifo(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The authorized-keys script must open no path that is not a regular file. A
// planted FIFO is the case: the in-process tier reads one as empty (localfs's
// non-blocking open), so the shell side skips it, and the fixture's real key file
// still arrives. Both FIFOs sort after the files that answer, so a script that
// opens its lists in order reaches one and — without the guard — is killed by the
// deadline here (this test was verified to fail against the unguarded script).
func TestAuthorizedKeysScriptSkipsPlantedFifos(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home", "lab")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(key, []byte("ssh-ed25519 AAAAfixture lab@host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The config stack names one file that answers and carries a FIFO beside it.
	configDir := filepath.Join(root, "ssh")
	config := filepath.Join(configDir, "sshd_config")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("AuthorizedKeysFile "+key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plantFifo(t, filepath.Join(configDir, "zz-planted.conf"))

	out := runScriptBounded(t, authorizedKeysScriptAt([]string{config, filepath.Join(configDir, "zz-planted.conf")}, []string{filepath.Join(root, "home", "*")}))
	if !strings.Contains(out, "AAAAfixture") {
		t.Errorf("the real key file should still be read, got %q", out)
	}
}

// The second reader of that script opens a path the config names, which can be
// anything on the host: a spec pointing at a FIFO is skipped rather than read.
func TestAuthorizedKeysScriptSkipsAFifoNamedByTheConfig(t *testing.T) {
	root := t.TempDir()
	fifoPath := filepath.Join(root, "named-keys")
	plantFifo(t, fifoPath)
	config := filepath.Join(root, "sshd_config")
	if err := os.WriteFile(config, []byte("AuthorizedKeysFile "+fifoPath+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out := runScriptBounded(t, authorizedKeysScriptAt([]string{config}, []string{filepath.Join(root, "home", "*")}))
	if strings.Contains(out, "named-keys") {
		t.Errorf("the FIFO the config named should carry no section, got %q", out)
	}
}
