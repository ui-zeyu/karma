package session

import (
	"strings"
	"testing"
)

func TestParseSSHDestination(t *testing.T) {
	cases := []struct {
		in   string
		want SSHDestination
	}{
		{"10.0.0.8", SSHDestination{Host: "10.0.0.8", Port: 22}},
		{"root@10.0.0.8", SSHDestination{User: "root", Host: "10.0.0.8", Port: 22}},
		{"ssh://root@10.0.0.8:2222", SSHDestination{User: "root", Host: "10.0.0.8", Port: 2222}},
		{"ssh://10.0.0.8", SSHDestination{Host: "10.0.0.8", Port: 22}},
		{"ssh://[::1]:22", SSHDestination{Host: "::1", Port: 22}},
		{"ssh://root@[2001:db8::1]", SSHDestination{User: "root", Host: "2001:db8::1", Port: 22}},
	}
	for _, c := range cases {
		got, err := ParseSSHDestination(c.in)
		if err != nil {
			t.Errorf("ParseSSHDestination(%q) errored: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseSSHDestination(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestParseSSHDestinationErrors(t *testing.T) {
	bad := []struct {
		in      string
		wantErr string
	}{
		{"", "not a valid destination"},
		{"10.0.0.8:2222", "non-URI form has no colon"}, // non-URI form has no colon
		{"root@10.0.0.8:22", "non-URI form has no colon"},
		{"ssh://::1", "IPv6 address requires brackets"},
		{"ssh://host:0", "port 0 out of range"},
		{"ssh://host:99999", "port 99999 out of range"},
		{"ssh://host:abc", `port "abc" is not a number`},
	}
	for _, c := range bad {
		got, err := ParseSSHDestination(c.in)
		if err == nil {
			t.Errorf("ParseSSHDestination(%q) = %+v, want error", c.in, got)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("ParseSSHDestination(%q) errored %q, want it to mention %q", c.in, err, c.wantErr)
		}
	}
}

func TestDestinationDisplay(t *testing.T) {
	cases := []struct {
		in   SSHDestination
		want string
	}{
		{SSHDestination{User: "root", Host: "10.0.0.8", Port: 22}, "root@10.0.0.8"},
		{SSHDestination{User: "root", Host: "10.0.0.8", Port: 2222}, "root@10.0.0.8:2222"},
		{SSHDestination{Host: "10.0.0.8", Port: 22}, "10.0.0.8"},
	}
	for _, c := range cases {
		if got := c.in.Display(); got != c.want {
			t.Errorf("Display(%+v) = %q, want %q", c.in, got, c.want)
		}
	}
}
