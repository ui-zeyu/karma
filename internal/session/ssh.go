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
	"net"
	"os"
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

// defaultIdentities is the default private key locations when -i is not given, matching OpenSSH's default search order.
func defaultIdentities() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return lo.FilterMap([]string{"id_ed25519", "id_ecdsa", "id_rsa"}, func(name string, _ int) (string, bool) {
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

// SshTransport is the SSH channel factory. A successful Open returns an SshSession that reuses the connection.
type SshTransport struct {
	Destination SshDestination
	Port        int // 0 uses Destination.Port
	Identities  []string
	HostKey     HostKeyMode
	Password    string // empty string uses only public keys; password comes from --password
}

// Name is the channel display name.
func (t *SshTransport) Name() string { return "ssh" }

// Platform: the SSH channel is always the Linux directory.
func (t *SshTransport) Platform() model.Platform { return model.Linux }

// Session is the channel protocol shared with Transport. Runner depends only on
// the interface here: swapping channels on the same platform = implement another Session.
type Session interface {
	Name() string
	Target() string
	Run(inv model.Invocation, timeout time.Duration, lineLimit int) model.RunResult
	Close() error
}

// Transport is the channel factory: a successful Open returns a usable Session.
type Transport interface {
	Name() string
	Platform() model.Platform
	Open() (Session, error)
}

// Open establishes the connection. The password comes only from --password;
// without it only public key auth is used, and rejection fails immediately with no interactive input.
func (t *SshTransport) Open() (Session, error) {
	knownHosts, err := loadKnownHosts()
	if err != nil {
		return nil, err
	}
	callback, err := t.hostKeyCallback(knownHosts)
	if err != nil {
		return nil, err
	}
	keys, agentConn, err := t.publicKeyAuth()
	if err != nil {
		return nil, err
	}
	// On auth failure or a mid-way error, close the agent connection; a successful session hands it to Close.
	var opened *SshSession
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
		opened = &SshSession{client: client, target: t.Destination.Display(), agent: agentConn}
		return opened, nil
	}
	// The password comes only from --password; without it, use public keys only and error directly on auth failure
	if t.Password != "" {
		return open(append(keys, passwordAuth(t.Password)...))
	}
	return open(keys)
}

var errAuthFailed = errors.New("ssh authentication failed")

func (t *SshTransport) connect(auth []ssh.AuthMethod, callback ssh.HostKeyCallback) (*ssh.Client, error) {
	port := t.Port
	if port == 0 {
		port = t.Destination.Port
	}
	addr := net.JoinHostPort(t.Destination.Host, strconv.Itoa(port))
	cfg := &ssh.ClientConfig{
		User:            t.user(),
		Auth:            auth,
		HostKeyCallback: callback,
		Timeout:         sshTimeout,
	}
	conn, err := net.DialTimeout("tcp", addr, sshTimeout)
	if err != nil {
		if isTimeout(err) {
			return nil, fmt.Errorf("connection timed out (%gs): %s", sshTimeout.Seconds(), t.Destination.Display())
		}
		return nil, err
	}
	client, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		if isAuthFailure(err) {
			return nil, fmt.Errorf("%w (use --password or allow a public key): %v", errAuthFailed, err)
		}
		return nil, err
	}
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

func (t *SshTransport) user() string {
	if t.Destination.User != "" {
		return t.Destination.User
	}
	return os.Getenv("USER")
}

// publicKeyAuth gathers available public keys: agent signers + explicit key files + default keys.
func (t *SshTransport) publicKeyAuth() ([]ssh.AuthMethod, io.Closer, error) {
	var methods []ssh.AuthMethod
	var agentConn io.Closer
	fail := func(err error) ([]ssh.AuthMethod, io.Closer, error) {
		if agentConn != nil {
			_ = agentConn.Close()
		}
		return nil, nil, err
	}
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
	for _, path := range identities {
		raw, err := os.ReadFile(path)
		if err != nil {
			return fail(fmt.Errorf("private key file does not exist: %s", path))
		}
		key, err := ssh.ParsePrivateKey(raw)
		if err != nil {
			var missing *ssh.PassphraseMissingError
			if errors.As(err, &missing) && t.Password != "" {
				key, err = ssh.ParsePrivateKeyWithPassphrase(raw, []byte(t.Password))
			}
			if err != nil {
				return fail(fmt.Errorf("failed to parse private key %s: %w", path, err))
			}
		}
		methods = append(methods, ssh.PublicKeys(key))
	}
	return methods, agentConn, nil
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

// hostKeyCallback returns the verification callback for the mode.
func (t *SshTransport) hostKeyCallback(known knownHostsDB) (ssh.HostKeyCallback, error) {
	switch t.HostKey {
	case HostKeyNo:
		return ssh.InsecureIgnoreHostKey(), nil
	case HostKeyYes:
		return knownhosts.New(known.paths...)
	default:
		return known.acceptNew(), nil
	}
}

// --- known_hosts: accept-new must decide "recorded or not, key matches or not" itself ---

type knownHostsDB struct {
	paths   []string
	entries []knownHostEntry
}

type knownHostEntry struct {
	patterns []string
	keys     map[string][]ssh.PublicKey // type name -> all records of that type
}

// loadKnownHosts loads the default known_hosts; a missing file is treated as an empty table.
func loadKnownHosts() (knownHostsDB, error) {
	home, _ := os.UserHomeDir()
	paths := []string{filepath.Join(home, ".ssh", "known_hosts"), "/etc/ssh/ssh_known_hosts"}
	db := knownHostsDB{paths: paths}
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if entry, ok := parseKnownHostLine(scanner.Text()); ok {
				db.entries = append(db.entries, entry)
			}
		}
		file.Close()
	}
	return db, nil
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
func (db knownHostsDB) acceptNew() ssh.HostKeyCallback {
	return func(host string, _ net.Addr, key ssh.PublicKey) error {
		names := hostNamesFor(host)
		var recorded []ssh.PublicKey
		for _, entry := range db.entries {
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
