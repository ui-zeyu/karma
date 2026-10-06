// logindSessionsIn over a fixture directory: the reference FIFOs systemd 255+
// parks next to the session state files must never be opened — reading one
// blocks forever, which is the bug this test pins.

//go:build unix

package native

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLogindSessionsSkipsReferenceFifos(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"c1": "UID=0\nUSER=root\nCLASS=user\n",
		"2":  "UID=1000\nCLASS=user-early\n",
		"7":  "UID=0\nCLASS=manager\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Mkfifo(filepath.Join(dir, "4242.ref"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Without the regular-file filter this hangs in open(2); the test finishing
	// is the assertion.
	count, ok := logindSessionsIn(dir)
	if !ok || count != 2 {
		t.Fatalf("logindSessionsIn = %d, %v; want 2, true", count, ok)
	}
	if _, ok := logindSessionsIn(t.TempDir()); ok {
		t.Fatal("an empty session directory should report no answer")
	}
}
