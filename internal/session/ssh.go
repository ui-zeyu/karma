// SSH channel: command rendering reuses shellcmd, execution uses x/crypto/ssh.
//
// Host key verification: default no -- allow everything (including recorded but
// changed keys, to fit contest targets reinstalled repeatedly); accept-new
// accepts new hosts and rejects recorded but changed keys (matching OpenSSH
// semantics); yes strictly verifies known_hosts. Both consulting modes read the
// records through x/crypto's knownhosts, which owns the file format: hashed
// host names, wildcard and negated patterns, @cert-authority and @revoked.

package session

import (
	"context"
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
	// pace states this channel's own waiting (see pace); the zero value is the
	// shipped one, so a caller never has to state it.
	pace pace
}

// Platform is always the Linux directory: the SSH channel never targets Windows.
func (t *SSHTransport) Platform() model.Platform { return model.Linux }

// Open establishes the connection. The password comes only from --password;
// without it only public key auth is used, and rejection fails immediately with no interactive input.
func (t *SSHTransport) Open(ctx context.Context) (Session, error) {
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
		client, err := t.connect(ctx, auth, callback)
		if err != nil {
			return nil, err
		}
		opened = &SSHSession{client: client, agent: agentConn, target: t.Destination.Display(), pace: t.pace}
		return opened, nil
	}
	// The password comes only from --password; without it, use public keys only and error directly on auth failure
	if t.Password != "" {
		return open(append(keys, passwordAuth(t.Password)...))
	}
	return open(keys)
}

func (t *SSHTransport) connect(ctx context.Context, auth []ssh.AuthMethod, callback ssh.HostKeyCallback) (*ssh.Client, error) {
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
	// next command hanging until its deadline
	bound := t.pace.resolved().sshSetup
	dialer := &net.Dialer{Timeout: bound, KeepAlive: 30 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if isTimeout(err) {
			return nil, fmt.Errorf("connection timed out (%gs): %s", bound.Seconds(), t.Destination.Display())
		}
		return nil, err
	}
	// The handshake has no context to give it (ClientConfig.Timeout only bounds
	// ssh.Dial's own dial), so bound it on the connection: the earlier of the
	// library's own bound and the run's deadline. A server that accepts the
	// connection and then stalls would hang the whole run here.
	_ = conn.SetDeadline(deadlineWithin(ctx, bound))
	client, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		// Ctrl-C during a handshake is the operator ending the run, which the
		// command line reports as an interruption rather than as a failed
		// connection.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if isTimeout(err) {
			return nil, fmt.Errorf("handshake with %s timed out (%gs)", t.Destination.Display(), bound.Seconds())
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

// deadlineWithin is the earlier of a library's own bound and the run's deadline:
// a handshake must not outlive either.
func deadlineWithin(ctx context.Context, bound time.Duration) time.Time {
	limit := time.Now().Add(bound)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(limit) {
		return deadline
	}
	return limit
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
		return knownHostsCallback(knownHostsPaths())
	default:
		verify, err := knownHostsCallback(knownHostsPaths())
		if err != nil {
			return nil, err
		}
		return acceptNewCheck(verify), nil
	}
}

// --- known_hosts: accept-new must decide "recorded or not, key matches or not" itself ---

// knownHostsPaths are the files OpenSSH reads, in its order.
func knownHostsPaths() []string {
	home, _ := os.UserHomeDir()
	return []string{filepath.Join(home, ".ssh", "known_hosts"), "/etc/ssh/ssh_known_hosts"}
}

// knownHostsCallback builds the library's verifier over the files that exist: it
// reads the records itself, including the hashed host names, the wildcard and
// negated patterns, and the @cert-authority and @revoked markers. A missing
// file is skipped because knownhosts.New fails on one, and a machine with no
// known_hosts at all is a machine where every host is new.
func knownHostsCallback(paths []string) (ssh.HostKeyCallback, error) {
	var files []string
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			files = append(files, path)
		}
	}
	if len(files) == 0 {
		empty := &knownhosts.KeyError{}
		return func(string, net.Addr, ssh.PublicKey) error { return empty }, nil
	}
	return knownhosts.New(files...)
}

// acceptNewCheck is OpenSSH's StrictHostKeyChecking=accept-new over the
// library's verifier: a recorded key that matches is accepted, a host with no
// record is new (the library says so with a KeyError whose Want is empty), and a
// record that does not match, or a key the file marks revoked, is refused.
func acceptNewCheck(verify ssh.HostKeyCallback) ssh.HostKeyCallback {
	return func(host string, remote net.Addr, key ssh.PublicKey) error {
		err := verify(host, remote, key)
		if err == nil {
			return nil
		}
		var unknown *knownhosts.KeyError
		if errors.As(err, &unknown) && len(unknown.Want) == 0 {
			return nil
		}
		return err
	}
}
