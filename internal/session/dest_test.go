package session

import (
	"testing"
)

func TestParseSSHDestination(t *testing.T) {
	cases := []struct {
		in   string
		want SshDestination
	}{
		{"10.0.0.8", SshDestination{Host: "10.0.0.8", Port: 22}},
		{"root@10.0.0.8", SshDestination{User: "root", Host: "10.0.0.8", Port: 22}},
		{"ssh://root@10.0.0.8:2222", SshDestination{User: "root", Host: "10.0.0.8", Port: 2222}},
		{"ssh://10.0.0.8", SshDestination{Host: "10.0.0.8", Port: 22}},
		{"ssh://[::1]:22", SshDestination{Host: "::1", Port: 22}},
		{"ssh://root@[2001:db8::1]", SshDestination{User: "root", Host: "2001:db8::1", Port: 22}},
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
	bad := []string{
		"",
		"10.0.0.8:2222", // non-URI form has no colon
		"root@10.0.0.8:22",
		"ssh://::1",    // IPv6 needs brackets
		"ssh://host:0", // port out of range
		"ssh://host:99999",
		"ssh://host:abc", // port not a number
	}
	for _, in := range bad {
		if got, err := ParseSSHDestination(in); err == nil {
			t.Errorf("ParseSSHDestination(%q) = %+v, want error", in, got)
		}
	}
}

func TestDestinationDisplay(t *testing.T) {
	cases := []struct {
		in   SshDestination
		want string
	}{
		{SshDestination{User: "root", Host: "10.0.0.8", Port: 22}, "root@10.0.0.8"},
		{SshDestination{User: "root", Host: "10.0.0.8", Port: 2222}, "root@10.0.0.8:2222"},
		{SshDestination{Host: "10.0.0.8", Port: 22}, "10.0.0.8"},
	}
	for _, c := range cases {
		if got := c.in.Display(); got != c.want {
			t.Errorf("Display(%+v) = %q, want %q", c.in, got, c.want)
		}
	}
}
