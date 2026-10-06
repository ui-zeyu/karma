package session

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
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

// hashedHost is the |1|salt|hmac form OpenSSH writes with HashKnownHosts on.
func hashedHost(t *testing.T, host string) string {
	t.Helper()
	salt := []byte("karma-test-salt")
	mac := hmac.New(sha1.New, salt)
	mac.Write([]byte(host))
	return "|1|" + base64.StdEncoding.EncodeToString(salt) + "|" +
		base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// accept-new is the default mode's verdict, and it decides whether a changed
// host key is refused: the file is read like OpenSSH reads it, a recorded key
// is accepted, a different key for a recorded host is refused, an unrecorded
// host is new, and a hashed record is consulted. Marker lines (@cert-authority)
// are not records.
func TestKnownHostsAcceptNewDecides(t *testing.T) {
	recorded := testPublicKey(t, 1)
	other := testPublicKey(t, 3)
	changed := testPublicKey(t, 2)

	path := filepath.Join(t.TempDir(), "known_hosts")
	content := strings.Join([]string{
		"# a comment",
		knownHostsLine("@cert-authority ca.example", other),
		knownHostsLine("recorded.example", recorded),
		knownHostsLine(hashedHost(t, "hashed.example"), recorded),
		"a line that is not a record",
		"broken.example ssh-ed25519 not-base64",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	entries := loadKnownHostEntries([]string{path, filepath.Join(t.TempDir(), "absent")})
	if len(entries) != 2 {
		t.Fatalf("comments, marker lines and malformed records are not entries: %+v", entries)
	}
	callback := acceptNew(entries)
	cases := []struct {
		name    string
		host    string
		key     ssh.PublicKey
		wantErr bool
	}{
		{"the recorded key is accepted", "recorded.example:22", recorded, false},
		{"a changed key is refused", "recorded.example:22", changed, true},
		{"the port does not hide a record", "recorded.example:2200", changed, true},
		{"an unrecorded host is new", "new.example:22", changed, false},
		{"a hashed record still matches", "hashed.example:22", recorded, false},
		{"a changed key under a hashed record is refused", "hashed.example:22", changed, true},
		{"a marker line is not a record", "ca.example:22", changed, false},
	}
	for _, c := range cases {
		err := callback(c.host, nil, c.key)
		switch {
		case c.wantErr && err == nil:
			t.Errorf("%s: %s should be refused", c.name, c.host)
		case !c.wantErr && err != nil:
			t.Errorf("%s: %s should be accepted: %v", c.name, c.host, err)
		}
	}
}

// The names a known_hosts pattern is matched against follow OpenSSH: the
// host:port form, the bare host, and the bracketed form for a non-default port.
func TestHostNamesFor(t *testing.T) {
	cases := []struct {
		host string
		want []string
	}{
		{"host.example:22", []string{"host.example:22", "host.example"}},
		{"host.example:2222", []string{"host.example:2222", "host.example", "[host.example]:2222"}},
		{"host.example", []string{"host.example"}},
	}
	for _, c := range cases {
		got := hostNamesFor(c.host)
		if len(got) != len(c.want) {
			t.Errorf("hostNamesFor(%q) = %q, want %q", c.host, got, c.want)
			continue
		}
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Errorf("hostNamesFor(%q) = %q, want %q", c.host, got, c.want)
			}
		}
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
	previous := uploadStall
	uploadStall = 20 * time.Millisecond
	defer func() { uploadStall = previous }()

	release := make(chan struct{})
	var stalled atomic.Bool
	err := writeUpload(blockingWriter{release}, make([]byte, uploadChunk), &stalled,
		func() { close(release) })
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
	previous := uploadStall
	uploadStall = 100 * time.Millisecond
	defer func() { uploadStall = previous }()

	var stalled atomic.Bool
	slow := writerFunc(func(p []byte) (int, error) {
		time.Sleep(20 * time.Millisecond)
		return len(p), nil
	})
	if err := writeUpload(slow, make([]byte, 3*uploadChunk), &stalled, func() {}); err != nil {
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
