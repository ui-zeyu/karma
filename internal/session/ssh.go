// SSH channel: command rendering reuses shellcmd, execution uses x/crypto/ssh.
//
// Host key verification: default no -- allow everything (including recorded but
// changed keys, to fit contest targets reinstalled repeatedly); accept-new
// accepts new hosts and rejects recorded but changed keys (matching OpenSSH
// semantics); yes strictly verifies known_hosts.

package session

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/samber/lo"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"karma/internal/model"
)

const (
	closeGrace = 5 * time.Second
	sshTimeout = 30 * time.Second
)

// defaultIdentities is the default private key locations when -i is not given,
// matching OpenSSH's default search order (hardware-key variants included).
func defaultIdentities() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return lo.FilterMap([]string{"id_ed25519", "id_ed25519_sk", "id_ecdsa", "id_ecdsa_sk", "id_rsa"}, func(name string, _ int) (string, bool) {
		path := filepath.Join(home, ".ssh", name)
		info, err := os.Stat(path)
		return path, err == nil && !info.IsDir()
	})
}

// HostKeyMode is the SSH host key verification mode, matching OpenSSH's StrictHostKeyChecking.
type HostKeyMode int

const (
	HostKeyNo HostKeyMode = iota
	HostKeyAcceptNew
	HostKeyYes
)

// ParseHostKeyMode parses the verification mode by OpenSSH spelling.
func ParseHostKeyMode(text string) (HostKeyMode, error) {
	switch text {
	case "yes":
		return HostKeyYes, nil
	case "accept-new":
		return HostKeyAcceptNew, nil
	case "no":
		return HostKeyNo, nil
	}
	return HostKeyNo, fmt.Errorf("StrictHostKeyChecking must be no|accept-new|yes (got: %s)", text)
}

// SSHTransport is the SSH channel factory. A successful Open returns an SSHSession that reuses the connection.
type SSHTransport struct {
	Destination SSHDestination
	Port        int // 0 uses Destination.Port
	Identities  []string
	HostKey     HostKeyMode
	Password    string // empty string uses only public keys; password comes from --password
}

// Platform is always the Linux directory: the SSH channel never targets Windows.
func (t *SSHTransport) Platform() model.Platform { return model.Linux }

// Open establishes the connection. The password comes only from --password;
// without it only public key auth is used, and rejection fails immediately with no interactive input.
func (t *SSHTransport) Open() (Session, error) {
	callback, err := t.hostKeyCallback()
	if err != nil {
		return nil, err
	}
	keys, agentConn, err := t.publicKeyAuth()
	if err != nil {
		return nil, err
	}
	// On auth failure or a mid-way error, close the agent connection; a successful session hands it to Close.
	var opened *SSHSession
	defer func() {
		if opened == nil && agentConn != nil {
			_ = agentConn.Close()
		}
	}()
	open := func(auth []ssh.AuthMethod) (Session, error) {
		client, err := t.connect(auth, callback)
		if err != nil {
			return nil, err
		}
		opened = &SSHSession{client: client, agent: agentConn}
		return opened, nil
	}
	// The password comes only from --password; without it, use public keys only and error directly on auth failure
	if t.Password != "" {
		return open(append(keys, passwordAuth(t.Password)...))
	}
	return open(keys)
}

func (t *SSHTransport) connect(auth []ssh.AuthMethod, callback ssh.HostKeyCallback) (*ssh.Client, error) {
	port := t.Port
	if port == 0 {
		port = t.Destination.Port
	}
	addr := net.JoinHostPort(t.Destination.Host, strconv.Itoa(port))
	cfg := &ssh.ClientConfig{
		User:            t.user(),
		Auth:            auth,
		HostKeyCallback: callback,
	}
	// Keepalive on: a collection run holds the connection for minutes, and a
	// NAT or firewall that silently drops idle TCP would otherwise leave the
	// next command hanging until its timeout
	dialer := &net.Dialer{Timeout: sshTimeout, KeepAlive: 30 * time.Second}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		if isTimeout(err) {
			return nil, fmt.Errorf("connection timed out (%gs): %s", sshTimeout.Seconds(), t.Destination.Display())
		}
		return nil, err
	}
	// The handshake has no deadline of its own (ClientConfig.Timeout only
	// bounds ssh.Dial's own dial): a server that accepts the connection and
	// then stalls would hang the whole run here. Bound it, release it once the
	// connection is up.
	_ = conn.SetDeadline(time.Now().Add(sshTimeout))
	client, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		if isTimeout(err) {
			return nil, fmt.Errorf("handshake with %s timed out (%gs)", t.Destination.Display(), sshTimeout.Seconds())
		}
		if isAuthFailure(err) {
			return nil, fmt.Errorf("ssh authentication failed (use --password or allow a public key): %v", err)
		}
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	go ssh.DiscardRequests(reqs)
	return ssh.NewClient(client, chans, reqs), nil
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// isAuthFailure: auth failure has no typed error, so recognition falls to the
// x/crypto error text; that wording has not changed for years, and a match yields an actionable hint.
func isAuthFailure(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "unable to authenticate")
}

// user is the SSH login user: an explicit user@host wins, then the USER
// environment variable, then the OS account (USER is unset in some service
// contexts and on Windows).
func (t *SSHTransport) user() string {
	if t.Destination.User != "" {
		return t.Destination.User
	}
	if name := os.Getenv("USER"); name != "" {
		return name
	}
	if current, err := user.Current(); err == nil {
		return current.Username
	}
	return ""
}

// publicKeyAuth gathers available public keys: agent signers + explicit key files + default keys.
//
// A candidate that cannot be used is skipped, not fatal: a passphrase-protected
// ~/.ssh/id_rsa is common, and dropping it must not discard the ssh-agent signers
// or the other key files that could answer. The first failure is remembered and
// returned only when no candidate at all is left, so a run with nothing to
// authenticate with still says why.
func (t *SSHTransport) publicKeyAuth() ([]ssh.AuthMethod, io.Closer, error) {
	var methods []ssh.AuthMethod
	var agentConn io.Closer
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			signers, err := agent.NewClient(conn).Signers()
			if err != nil || len(signers) == 0 {
				_ = conn.Close()
			} else {
				methods = append(methods, ssh.PublicKeys(signers...))
				agentConn = conn
			}
		}
	}
	identities := t.Identities
	if len(identities) == 0 {
		identities = defaultIdentities()
	}
	var skipped error
	for _, path := range identities {
		key, err := loadIdentity(path, t.Password)
		if err != nil {
			if skipped == nil {
				skipped = err
			}
			continue
		}
		methods = append(methods, ssh.PublicKeys(key))
	}
	if len(methods) == 0 && skipped != nil {
		return nil, agentConn, skipped
	}
	return methods, agentConn, nil
}

// loadIdentity reads one private key file. A passphrase-protected key is unlocked
// with the command-line password when one was given; without it the error names
// the one flag that can help.
func loadIdentity(path string, password string) (ssh.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("private key file does not exist: %s", path)
		}
		return nil, fmt.Errorf("cannot read private key %s: %v", path, err)
	}
	key, err := ssh.ParsePrivateKey(raw)
	if err == nil {
		return key, nil
	}
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if password == "" {
			return nil, fmt.Errorf("private key %s is passphrase protected: pass --password to unlock it", path)
		}
		unlocked, retryErr := ssh.ParsePrivateKeyWithPassphrase(raw, []byte(password))
		if retryErr != nil {
			return nil, fmt.Errorf("cannot use private key %s: %w", path, retryErr)
		}
		return unlocked, nil
	}
	return nil, fmt.Errorf("cannot use private key %s: %w", path, err)
}

// passwordAuth offers two password paths: password and keyboard-interactive each
// once, so either server method can be answered; the keyboard-interactive response is also this command-line password.
func passwordAuth(password string) []ssh.AuthMethod {
	return []ssh.AuthMethod{
		ssh.Password(password),
		ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
			return lo.Times(len(questions), func(int) string { return password }), nil
		}),
	}
}

// hostKeyCallback returns the verification callback for the mode. known_hosts is
// only read when the mode consults it: the default mode accepts anything and
// never opens the file.
func (t *SSHTransport) hostKeyCallback() (ssh.HostKeyCallback, error) {
	switch t.HostKey {
	case HostKeyNo:
		return ssh.InsecureIgnoreHostKey(), nil
	case HostKeyYes:
		return knownhosts.New(knownHostsPaths()...)
	default:
		return acceptNew(loadKnownHostEntries(knownHostsPaths())), nil
	}
}

// --- known_hosts: accept-new must decide "recorded or not, key matches or not" itself ---

// knownHostEntry is one parsed known_hosts line: its host patterns (which may be
// negated with a leading `!`) and the keys recorded for it by key type.
type knownHostEntry struct {
	patterns []string
	keys     map[string][]ssh.PublicKey // type name -> all records of that type
}

// knownHostsPaths are the files OpenSSH reads, in its order.
func knownHostsPaths() []string {
	home, _ := os.UserHomeDir()
	return []string{filepath.Join(home, ".ssh", "known_hosts"), "/etc/ssh/ssh_known_hosts"}
}

// loadKnownHostEntries parses every readable known_hosts file into an entry
// table; a missing file contributes nothing and leaves the table empty.
func loadKnownHostEntries(paths []string) []knownHostEntry {
	var entries []knownHostEntry
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if entry, ok := parseKnownHostLine(scanner.Text()); ok {
				entries = append(entries, entry)
			}
		}
		file.Close()
	}
	return entries
}

// parseKnownHostLine parses one known_hosts line (@cert/@revoked marker lines are
// skipped; hashed host names are parsed by the library into a pattern list).
func parseKnownHostLine(line string) (knownHostEntry, bool) {
	marker, patterns, key, _, _, err := ssh.ParseKnownHosts([]byte(line))
	if err != nil || marker != "" || len(patterns) == 0 {
		return knownHostEntry{}, false
	}
	entry := knownHostEntry{patterns: patterns, keys: map[string][]ssh.PublicKey{}}
	entry.keys[key.Type()] = append(entry.keys[key.Type()], key)
	return entry, true
}

// acceptNew allows a new host, rejects a changed key, and allows a recorded key.
func acceptNew(entries []knownHostEntry) ssh.HostKeyCallback {
	return func(host string, _ net.Addr, key ssh.PublicKey) error {
		names := hostNamesFor(host)
		var recorded []ssh.PublicKey
		for _, entry := range entries {
			if !entry.matchesAny(names) {
				continue
			}
			recorded = append(recorded, entry.keys[key.Type()]...)
		}
		if len(recorded) == 0 {
			// No record: accept the new key
			return nil
		}
		if lo.SomeBy(recorded, func(existing ssh.PublicKey) bool {
			return bytes.Equal(existing.Marshal(), key.Marshal())
		}) {
			return nil
		}
		// Recorded but different key: reject (possible man-in-the-middle or reinstall)
		return fmt.Errorf("host key for %s has changed in known_hosts", host)
	}
}

func hostNamesFor(hostPort string) []string {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return []string{hostPort}
	}
	names := []string{hostPort, host}
	if port != "22" {
		names = append(names, "["+host+"]:"+port)
	}
	return names
}

// matchesAny reports whether the entry applies to the target host: OpenSSH
// semantics -- an entry applies when a positive pattern matches and no negated
// pattern matches. Negated patterns (`!host`) take precedence over positive ones.
func (e knownHostEntry) matchesAny(names []string) bool {
	matched := false
	for _, pattern := range e.patterns {
		negated := strings.HasPrefix(pattern, "!")
		if negated {
			pattern = pattern[1:]
		}
		for _, name := range names {
			if !matchKnownHostPattern(pattern, name) {
				continue
			}
			if negated {
				return false
			}
			matched = true
		}
	}
	return matched
}

// matchKnownHostPattern supports |1|hashed and wildcards; everything else is compared literally.
func matchKnownHostPattern(pattern, name string) bool {
	if strings.HasPrefix(pattern, "|1|") {
		parts := strings.Split(pattern, "|")
		if len(parts) != 4 {
			return false
		}
		salt, err1 := base64.StdEncoding.DecodeString(parts[2])
		want, err2 := base64.StdEncoding.DecodeString(parts[3])
		if err1 != nil || err2 != nil {
			return false
		}
		mac := hmac.New(sha1.New, salt)
		mac.Write([]byte(name))
		return hmac.Equal(mac.Sum(nil), want)
	}
	if strings.ContainsAny(pattern, "*?!") {
		ok, err := filepath.Match(pattern, name)
		return err == nil && ok
	}
	return pattern == name
}
