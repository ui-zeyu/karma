// TTYD channel: endpoint parsing, the transport, and the open-time probe.
//
// The channel reaches a target through a ttyd web terminal: the operator has a
// browser console on the host, karma connects to the same websocket endpoint as
// a second client and types its collection line into the terminal ttyd spawns
// for it. Each websocket connection gets its own process, so karma never
// touches the operator's session. ttyd's frame protocol carries a terminal, so
// the channel adapts around it: the script travels as one base64 line (no
// quoting hazards in whatever shell the operator runs), and the exit code
// travels as an in-band marker because the websocket close code only
// distinguishes zero from non-zero.

package session

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"karma/internal/model"
)

const (
	// ttydDefaultPort is ttyd's own listening default, used when a bare host
	// is given without a port.
	ttydDefaultPort = 7681
	// ttydDialTimeout bounds one websocket dial.
	ttydDialTimeout = 15 * time.Second
)

// ttydProbeWindow bounds the open-time probe: a broken endpoint fails once,
// here, instead of silently in every check. A variable so tests can shorten it.
var ttydProbeWindow = 10 * time.Second

// ParseTTYDEndpoint turns the command-line target into the websocket URL and
// the credential. Accepted forms: ws://[user:pass@]host[:port][/ws],
// wss://[user:pass@]host[:port][/ws], and the bare host[:port] (ws:// with
// ttyd's default port; IPv6 uses the URL's bracketed form). The path, when
// given, is the websocket endpoint (ttyd's default /ws, or /base/ws behind a
// reverse proxy). A query string is rejected: on an -a server it would inject
// arguments into the spawned process.
func ParseTTYDEndpoint(target string) (endpoint string, credential string, err error) {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return "", "", fmt.Errorf("the ttyd target is empty")
	}
	if !strings.Contains(trimmed, "://") {
		host, port, parseErr := parseBareHost(trimmed)
		if parseErr != nil {
			return "", "", parseErr
		}
		return fmt.Sprintf("ws://%s:%d/ws", host, port), "", nil
	}
	parsed, parseErr := url.Parse(trimmed)
	if parseErr != nil {
		return "", "", fmt.Errorf("%q is not a valid ttyd URL: %v", target, parseErr)
	}
	switch parsed.Scheme {
	case "ws", "wss":
	default:
		return "", "", fmt.Errorf("%q: the ttyd target scheme must be ws:// or wss://", target)
	}
	if parsed.Hostname() == "" {
		return "", "", fmt.Errorf("%q: the ttyd target needs a host", target)
	}
	if portText := parsed.Port(); portText != "" {
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > MaxPort {
			return "", "", fmt.Errorf("%q: port %s out of range 1-%d", target, portText, MaxPort)
		}
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", fmt.Errorf("%q: the ttyd target takes no query string or fragment", target)
	}
	if parsed.User != nil {
		// Username and Password come back decoded; a password may carry an @
		// through percent-encoding, and the split at the last @ already
		// decided where the host starts.
		credential = parsed.User.Username()
		if password, set := parsed.User.Password(); set {
			credential += ":" + password
		}
		parsed.User = nil
	}
	path := parsed.Path
	if path == "" || path == "/" {
		path = "/ws"
	}
	parsed.Path, parsed.RawQuery, parsed.Fragment = "", "", ""
	return parsed.String() + path, credential, nil
}

// parseBareHost reads host[:port] and [addr][:port], filling in ttyd's default
// port. An unbracketed IPv6 address has colons of its own and needs the URL
// form.
func parseBareHost(target string) (string, int, error) {
	if strings.HasPrefix(target, "[") {
		end := strings.Index(target, "]")
		if end < 0 {
			return "", 0, fmt.Errorf("%q: the ttyd target has no closing ] for an IPv6 address", target)
		}
		host := target[:end+1]
		rest := target[end+1:]
		if rest == "" {
			return host, ttydDefaultPort, nil
		}
		port, err := portAfterColon(rest)
		if err != nil {
			return "", 0, fmt.Errorf("%q: %v", target, err)
		}
		return host, port, nil
	}
	host, rest, hasColon := strings.Cut(target, ":")
	if host == "" {
		return "", 0, fmt.Errorf("%q: the ttyd target needs a host", target)
	}
	if !hasColon {
		return host, ttydDefaultPort, nil
	}
	if strings.Contains(rest, ":") {
		return "", 0, fmt.Errorf("%q: IPv6 needs brackets, expected ws://[addr] or ws://[addr]:port", target)
	}
	port, err := portAfterColon(":" + rest)
	if err != nil {
		return "", 0, fmt.Errorf("%q: %v", target, err)
	}
	return host, port, nil
}

func portAfterColon(rest string) (int, error) {
	text, ok := strings.CutPrefix(rest, ":")
	if !ok {
		return 0, fmt.Errorf("expected :port after the address")
	}
	port, err := strconv.Atoi(text)
	if err != nil {
		return 0, fmt.Errorf("port %q is not a number", text)
	}
	if port < 1 || port > MaxPort {
		return 0, fmt.Errorf("port %d out of range 1-%d", port, MaxPort)
	}
	return port, nil
}

// TTYDTransport is the ttyd channel factory: one websocket endpoint, an
// optional basic credential (ttyd's -c), and TLS verification modes for wss.
type TTYDTransport struct {
	Target     string // ws://[user:pass@]host[:port][/ws], wss://..., or bare host[:port]
	Credential string // user:pass; overrides any userinfo in the target
	Insecure   bool   // wss: accept any server certificate
	Pin        string // wss: hex SHA-256 of the leaf certificate, verified instead of the chain
}

// Platform is always the Linux directory: the ttyd channel never targets Windows.
func (t *TTYDTransport) Platform() model.Platform { return model.Linux }

// Open verifies the endpoint and probes the terminal once: client input must
// reach a shell and come back. A readonly deployment (ttyd from 1.7.4 without
// -W/--writable) fails here with the reason, instead of leaving every check to
// collect nothing.
func (t *TTYDTransport) Open(ctx context.Context) (Session, error) {
	endpoint, credential, err := ParseTTYDEndpoint(t.Target)
	if err != nil {
		return nil, err
	}
	if t.Credential != "" {
		credential = t.Credential
	}
	client, err := t.httpClient(endpoint)
	if err != nil {
		return nil, err
	}
	sess := &TTYDSession{
		endpoint: endpoint,
		token:    base64.StdEncoding.EncodeToString([]byte(credential)),
		header:   http.Header{},
		client:   client,
	}
	if credential != "" {
		sess.header.Set("Authorization", "Basic "+sess.token)
	}
	if err := sess.probe(ctx); err != nil {
		return nil, err
	}
	return sess, nil
}

// httpClient builds the HTTP client for the websocket dial: the default for
// ws, and the requested verification mode for wss (chain, pinned fingerprint,
// or anything). --insecure and --tls-pin are two different answers to a
// self-signed certificate; giving both is a mistake to refuse, not resolve.
func (t *TTYDTransport) httpClient(endpoint string) (*http.Client, error) {
	if !strings.HasPrefix(endpoint, "wss://") {
		return nil, nil
	}
	switch {
	case t.Insecure && t.Pin != "":
		return nil, fmt.Errorf("--insecure and --tls-pin answer the same question; give one")
	case t.Insecure:
		return &http.Client{Transport: &http.Transport{TLSClientConfig: insecureTLS()}}, nil
	case t.Pin != "":
		fingerprint, err := parsePin(t.Pin)
		if err != nil {
			return nil, err
		}
		return &http.Client{Transport: &http.Transport{TLSClientConfig: pinnedTLS(fingerprint)}}, nil
	}
	return nil, nil
}

// parsePin reads the certificate fingerprint: bare hex, or the sha256: prefixed
// spelling.
func parsePin(pin string) ([sha256.Size]byte, error) {
	var fingerprint [sha256.Size]byte
	text, ok := strings.CutPrefix(pin, "sha256:")
	if !ok {
		text = pin
	}
	raw, err := hex.DecodeString(strings.ToLower(text))
	if err != nil || len(raw) != sha256.Size {
		return fingerprint, fmt.Errorf("--tls-pin wants 64 hex characters (the certificate's SHA-256)")
	}
	copy(fingerprint[:], raw)
	return fingerprint, nil
}

// insecureTLS accepts any server certificate: the ws:// form already carries
// everything in the clear, this only says so for wss.
func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}

// pinnedTLS verifies the leaf certificate's SHA-256 against the fingerprint
// instead of the chain: the self-signed answer. InsecureSkipVerify is set
// because the pin itself is the verification.
func pinnedTLS(fingerprint [sha256.Size]byte) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, raw := range rawCerts {
				if sha256.Sum256(raw) == fingerprint {
					return nil
				}
			}
			return fmt.Errorf("no certificate in the chain matches the pinned fingerprint")
		},
	}
}
