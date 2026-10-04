package session

import (
	"errors"
	"testing"
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
