package session

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Auth failure has no typed error, so recognition can only fall to the x/crypto
// error text; this set of cases locks the recognition behavior, showing up here when the wording drifts.
func TestIsAuthFailure(t *testing.T) {
	t.Parallel()
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

// testPublicKey builds a deterministic ed25519 key, so a fixture known_hosts
// line can be written out and compared against the same key.
func testPublicKey(t *testing.T, seed byte) ssh.PublicKey {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	key, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// knownHostsLine renders one known_hosts record for a key.
func knownHostsLine(patterns string, key ssh.PublicKey) string {
	return patterns + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

// knownHostsFile writes a fixture file and returns its path.
func knownHostsFile(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// accept-new is the default mode's verdict, and it decides whether a changed
// host key is refused: a recorded key is accepted, a different key for a
// recorded host is refused, an unrecorded host is new, a hashed record is
// consulted, and a revoked record is refused. The file format itself — hashed
// host names, wildcard and negated patterns, the markers — belongs to
// x/crypto/ssh/knownhosts, which the verifier hands the file to.
func TestKnownHostsAcceptNewDecides(t *testing.T) {
	t.Parallel()
	recorded := testPublicKey(t, 1)
	changed := testPublicKey(t, 2)
	revoked := testPublicKey(t, 3)

	path := knownHostsFile(t,
		"# a comment",
		knownHostsLine("recorded.example", recorded),
		knownHostsLine("[port.example]:2222", recorded),
		knownHostsLine(knownhosts.HashHostname("hashed.example"), recorded),
		knownHostsLine("*.wild.example,!bad.wild.example", recorded),
		"@revoked revoked.example "+strings.TrimSpace(string(ssh.MarshalAuthorizedKey(revoked))),
		"",
	)
	verify, err := knownHostsCallback([]string{path, filepath.Join(t.TempDir(), "absent")})
	if err != nil {
		t.Fatal(err)
	}
	callback := acceptNewCheck(verify)
	cases := []struct {
		name    string
		host    string
		key     ssh.PublicKey
		wantErr bool
	}{
		{"the recorded key is accepted", "recorded.example:22", recorded, false},
		{"a changed key is refused", "recorded.example:22", changed, true},
		{"a bare host record covers the default port only", "recorded.example:2200", changed, false},
		{"a bracketed record is consulted on its own port", "port.example:2222", recorded, false},
		{"a changed key under a bracketed record is refused", "port.example:2222", changed, true},
		{"an unrecorded host is new", "new.example:22", changed, false},
		{"a hashed record still matches", "hashed.example:22", recorded, false},
		{"a changed key under a hashed record is refused", "hashed.example:22", changed, true},
		{"a wildcard record matches", "web.wild.example:22", recorded, false},
		{"a negated pattern keeps the record from applying", "bad.wild.example:22", changed, false},
		{"a revoked key is refused", "revoked.example:22", revoked, true},
	}
	for _, c := range cases {
		// The library reads the peer address as well as the host name, the way
		// the ssh client hands both to a callback.
		err := callback(c.host, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}, c.key)
		switch {
		case c.wantErr && err == nil:
			t.Errorf("%s: %s should be refused", c.name, c.host)
		case !c.wantErr && err != nil:
			t.Errorf("%s: %s should be accepted: %v", c.name, c.host, err)
		}
	}
}

// A record the library cannot read stops the mode that consults the file: a
// record karma cannot parse is one whose verdict it cannot trust, and the error
// names the file and the line. `no` never opens the file at all.
func TestKnownHostsMalformedRecordIsRefused(t *testing.T) {
	recorded := testPublicKey(t, 1)
	path := knownHostsFile(t,
		knownHostsLine("recorded.example", recorded),
		"broken.example ssh-ed25519 not-base64",
	)
	if _, err := knownHostsCallback([]string{path}); err == nil {
		t.Fatal("a known_hosts file with an unreadable record should stop the verifier")
	}
	if _, err := knownHostsCallback(nil); err != nil {
		t.Fatalf("no known_hosts at all is a machine where every host is new: %v", err)
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

// A target that stops draining the channel blocks a Write forever, and the
// command line's context only sees SIGINT: the idle bound is what ends such a
// transfer with something the operator can read.
func TestWriteUploadBoundsAStall(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	var stalled atomic.Bool
	err := writeUpload(blockingWriter{release}, make([]byte, uploadChunk), &stalled,
		func() { close(release) }, 20*time.Millisecond)
	if err == nil {
		t.Fatal("a write that never returns should end on the idle bound")
	}
	if !stalled.Load() {
		t.Fatal("the bound should be reported as the reason")
	}
}

// The bound measures the gap between chunks, so a slow link that keeps making
// progress finishes.
func TestWriteUploadProgressResetsTheBound(t *testing.T) {
	t.Parallel()
	var stalled atomic.Bool
	slow := writerFunc(func(p []byte) (int, error) {
		time.Sleep(20 * time.Millisecond)
		return len(p), nil
	})
	if err := writeUpload(slow, make([]byte, 3*uploadChunk), &stalled, func() {}, 100*time.Millisecond); err != nil {
		t.Fatalf("a moving transfer should not be a stall: %v", err)
	}
	if stalled.Load() {
		t.Fatal("a moving transfer is not a stall")
	}
}

// blockingWriter never completes until release is closed.
type blockingWriter struct{ release chan struct{} }

func (w blockingWriter) Write([]byte) (int, error) {
	<-w.release
	return 0, errors.New("channel closed")
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
