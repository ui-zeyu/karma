package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh/agent"
)

// Auth failure has no typed error, so recognition can only fall to the x/crypto
// error text; this set of cases locks the recognition behavior, showing up here when the wording drifts.
func TestIsAuthFailure(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{errors.New("ssh: unable to authenticate, attempted methods [none], no supported methods remain"), true},
		{errors.New("ssh: Unable to authenticate, attempted methods [publickey]"), true},
		{errors.New("ssh: handshake failed: EOF"), false},
		{errors.New("dial tcp 10.0.0.8:22: connect: connection refused"), false},
		{errors.New("ssh: host key mismatch"), false},
	}
	for _, c := range cases {
		if got := isAuthFailure(c.err); got != c.want {
			t.Errorf("isAuthFailure(%q) = %v, want %v", c.err, got, c.want)
		}
	}
}

// accept-new's entry-applies semantics match OpenSSH: a positive pattern matches and no negated pattern matches.
func TestKnownHostNegatedPatterns(t *testing.T) {
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEmpEMShviM+e4iAPoXY+2kHG7sRu8U/7mJtl04nLtxg"
	entry, ok := parseKnownHostLine("*.example.com,!bad.example.com " + key)
	if !ok {
		t.Fatal("the fixture line should parse into an entry")
	}
	if !entry.matchesAny([]string{"good.example.com"}) {
		t.Fatal("a host matched by a positive pattern should apply")
	}
	if entry.matchesAny([]string{"bad.example.com"}) {
		t.Fatal("a host matched by a negated pattern should not apply")
	}

	reversed, ok := parseKnownHostLine("!bad.example.com,*.example.com " + key)
	if !ok {
		t.Fatal("the fixture line should parse into an entry")
	}
	if reversed.matchesAny([]string{"bad.example.com"}) {
		t.Fatal("a negated pattern written first also applies")
	}
}

// --- private key candidates ---

// startTestAgent serves an in-process ssh-agent holding one ed25519 key and
// returns its SSH_AUTH_SOCK path. The socket lives in a short directory: a long
// path exceeds the unix socket limit on macOS.
func startTestAgent(t *testing.T) string {
	t.Helper()
	keyring := agent.NewKeyring()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("/tmp", "karma-agent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(keyring, conn) }()
		}
	}()
	return sock
}

// passphraseKeyHome makes ~/.ssh/id_rsa a passphrase-protected key under a
// private HOME, so the default identity search picks it up.
func passphraseKeyHome(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	home := t.TempDir()
	dir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("ssh-keygen", "-t", "rsa", "-b", "2048", "-N", "secret",
		"-f", filepath.Join(dir, "id_rsa"), "-q").CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	t.Setenv("HOME", home)
}

// A default key that cannot be used must not abort the key search: the agent
// signers gathered before it stay usable.
func TestPublicKeyAuthKeepsAgentWithUnusableDefaultKey(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", startTestAgent(t))
	passphraseKeyHome(t)

	methods, closer, err := (&SSHTransport{}).publicKeyAuth()
	if closer != nil {
		_ = closer.Close()
	}
	if err != nil {
		t.Fatalf("an unusable default key should not fail the search: %v", err)
	}
	if len(methods) == 0 {
		t.Fatal("the agent signers should still be offered")
	}
}

// With no usable candidate at all, the failure names the flag that unlocks the key.
func TestPublicKeyAuthReportsUnlockableKey(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	passphraseKeyHome(t)

	_, closer, err := (&SSHTransport{}).publicKeyAuth()
	if closer != nil {
		_ = closer.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "--password") {
		t.Fatalf("a key that needs a passphrase should point at --password: %v", err)
	}
}
