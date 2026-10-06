//go:build unix

package linux

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"karma/internal/checks/linux/native"
)

// runBodyBounded runs one in-process tier over a fixture under a deadline: a
// reader that parks in open(2) has no context to observe, so the test stops
// waiting and reports the regression instead of hanging with it.
func runBodyBounded(t *testing.T, body func(context.Context) (string, error)) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	done := make(chan string, 1)
	go func() {
		text, _ := body(ctx)
		done <- text
	}()
	select {
	case text := <-done:
		return text
	case <-ctx.Done():
		t.Fatal("the tier did not finish within 10s: a path it opened never answered")
		return ""
	}
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

// The authorized-keys tier opens no path that is not a regular file: a planted
// FIFO is the case. localfs's non-blocking open reads one as empty, so the
// fixture's real key file still arrives while the FIFO beside it contributes an
// empty section — before that guard the read parked in open(2) and the walk's
// deadline had to cut the check.
func TestAuthorizedKeysSkipsPlantedFifos(t *testing.T) {
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

	out := runBodyBounded(t, native.AuthorizedKeys([]string{filepath.Join(root, "home", "*")}, authorizedKeysDepth,
		[]string{config, filepath.Join(configDir, "zz-planted.conf")}))
	if !strings.Contains(out, "AAAAfixture") {
		t.Errorf("the real key file should still be read, got %q", out)
	}
}

// A directive can name any path on the host, a FIFO included: the path is read
// as empty rather than blocking the collection.
func TestAuthorizedKeysSkipsAFifoNamedByTheConfig(t *testing.T) {
	root := t.TempDir()
	fifoPath := filepath.Join(root, "named-keys")
	plantFifo(t, fifoPath)
	config := filepath.Join(root, "sshd_config")
	if err := os.WriteFile(config, []byte("AuthorizedKeysFile "+fifoPath+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out := runBodyBounded(t, native.AuthorizedKeys([]string{filepath.Join(root, "home", "*")}, authorizedKeysDepth, []string{config}))
	if strings.Contains(out, "named-keys") && strings.Contains(out, "ssh-") {
		t.Errorf("the FIFO the config named should carry no key, got %q", out)
	}
}
