// Endpoint parsing and payload shape: cross-platform, no shell involved.

package session

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"karma/internal/model"
)

func TestParseTTYDEndpoint(t *testing.T) {
	cases := []struct {
		in         string
		endpoint   string
		credential string
	}{
		{"ws://h", "ws://h/ws", ""},
		{"ws://h:80", "ws://h:80/ws", ""},
		{"wss://h:443/ws", "wss://h:443/ws", ""},
		{"wss://h/proxy/ws", "wss://h/proxy/ws", ""},
		{"ws://u:p@h:7681", "ws://h:7681/ws", "u:p"},
		{"ws://u:p%40x@h", "ws://h/ws", "u:p@x"},
		{"h", "ws://h:7681/ws", ""},
		{"h:80", "ws://h:80/ws", ""},
		{"[::1]", "ws://[::1]:7681/ws", ""},
		{"[::1]:80", "ws://[::1]:80/ws", ""},
	}
	for _, c := range cases {
		endpoint, credential, err := ParseTTYDEndpoint(c.in)
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		if endpoint != c.endpoint || credential != c.credential {
			t.Errorf("%s: got (%s, %s), want (%s, %s)", c.in, endpoint, credential, c.endpoint, c.credential)
		}
	}
}

func TestParseTTYDEndpointRejects(t *testing.T) {
	for _, target := range []string{
		"",
		"http://h",
		"ssh://h",
		"ws://",
		"ws://h/ws?arg=x",
		"ws://h/ws#frag",
		"ws://h:99999",
		"::1",
		"[::1",
		"h:notaport",
	} {
		if _, _, err := ParseTTYDEndpoint(target); err == nil {
			t.Errorf("%q should not parse", target)
		}
	}
}

func TestParsePin(t *testing.T) {
	fingerprint, err := parsePin("sha256:" + strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("prefixed pin: %v", err)
	}
	if fingerprint != parsePinOrFatal(t, strings.Repeat("ab", 32)) {
		t.Fatal("the prefix spelling and the bare spelling must agree")
	}
	for _, pin := range []string{"", "zz", strings.Repeat("ab", 31), strings.Repeat("g0", 32)} {
		if _, err := parsePin(pin); err == nil {
			t.Errorf("%q should not parse as a fingerprint", pin)
		}
	}
}

func parsePinOrFatal(t *testing.T, pin string) [32]byte {
	t.Helper()
	fingerprint, err := parsePin(pin)
	if err != nil {
		t.Fatalf("bare pin: %v", err)
	}
	return fingerprint
}

func TestTtydPayloadShape(t *testing.T) {
	payload := ttydPayload("exit 7", "deadbeef")
	for _, want := range []string{
		"export TERM=dumb",
		"unset COLUMNS",
		"stty cols 0 </dev/tty 2>/dev/null || :",
		"exec 3>&1",
		"printf '__KRM_deadbeef_S__\\n'",
		"__karma_err=$( ( exit 7 ) 2>&1 1>&3 3>&- ); __karma_rc=$?",
		"printf '__KRM_deadbeef_R_%d__\\n' \"$__karma_rc\"",
	} {
		if !strings.Contains(payload, want) {
			t.Errorf("payload misses %q:\n%s", want, payload)
		}
	}
}

func TestSplitTTYDRC(t *testing.T) {
	if body, code, ok := splitTTYDRC("__KRM_deadbeef_R_127__", "__KRM_deadbeef_R_"); !ok || code != 127 || body != "" {
		t.Fatalf("plain marker line: %q %d %v", body, code, ok)
	}
	// A body without its trailing newline glues in front of the marker.
	if body, code, ok := splitTTYDRC("tail__KRM_deadbeef_R_0__", "__KRM_deadbeef_R_"); !ok || code != 0 || body != "tail" {
		t.Fatalf("glued marker line: %q %d %v", body, code, ok)
	}
	for _, line := range []string{"__KRM_deadbeef_S__", "__KRM_deadbeef_R___", "x__KRM_deadbeef_R_1__tail"} {
		if _, _, ok := splitTTYDRC(line, "__KRM_deadbeef_R_"); ok {
			t.Errorf("%q should not split as an rc marker", line)
		}
	}
}

// The per-call marker salt must be unique across calls and hold no character a
// shell, printf or the marker match reads: crypto/rand.Text's alphabet is
// upper-case letters and digits.
func TestTTYDMarkerSaltIsUniqueAndShellSafe(t *testing.T) {
	seen := make(map[string]bool)
	for range 100 {
		token := markerSalt()
		if token == "" || strings.ContainsFunc(token, func(r rune) bool {
			return !('A' <= r && r <= 'Z') && !('0' <= r && r <= '9')
		}) {
			t.Fatalf("marker salt: %q", token)
		}
		if seen[token] {
			t.Fatalf("two markers collided: %s", token)
		}
		seen[token] = true
	}
}

// The probe's evidence classes must tell an echo from the payload: the marker
// as a substring of the encoded text (it can happen, letters inside base64)
// must never read as the payload having come back.
func TestTTYDProbeMarkerVersusEcho(t *testing.T) {
	marker := []byte("__KRM_PROBE_deadbeef__")
	echo := []byte(base64.StdEncoding.EncodeToString(append(marker, '\n')))
	payload := !bytes.Contains(echo, echo) && bytes.Contains(echo, marker)
	heard := bytes.Contains(echo, echo)
	if payload || !heard {
		t.Fatal("an echo frame must classify as echo, never as the payload")
	}
}

// Ctrl-C is the operator ending the run, not the endpoint dying: a dial cut by
// our own cancellation must not latch the channel lost, or the command line
// would report a lost channel (exit 2) where the interrupt (130) is the truth.
func TestTTYDCancelledDialDoesNotLoseTheChannel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sess := &TTYDSession{endpoint: "ws://127.0.0.1:1/ws"}
	if result := sess.Run(ctx, model.Shell{Script: "true"}, time.Second, 0); result.ExitCode != -1 {
		t.Fatalf("wanted a failed call, got %+v", result)
	}
	if sess.Lost() {
		t.Fatal("our own cancellation is not the endpoint going away")
	}
}

// An endpoint nothing answers is latched: every later call would fail the same
// way, so the runner stops queueing checks and the command line says so once.
func TestTTYDUnreachableEndpointIsLost(t *testing.T) {
	sess := &TTYDSession{endpoint: "ws://127.0.0.1:1/ws"}
	sess.Run(context.Background(), model.Shell{Script: "true"}, time.Second, 0)
	if !sess.Lost() {
		t.Fatal("a dial nothing answers must latch lost")
	}
}
