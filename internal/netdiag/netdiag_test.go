package netdiag

import (
	"net"
	"testing"
)

func TestStateWord(t *testing.T) {
	cases := []struct {
		netid string
		state uint8
		want  string
	}{
		{"tcp", 1, "ESTAB"},
		{"tcp", 10, "LISTEN"},
		{"tcp", 6, "TIME-WAIT"},
		{"tcp", 11, "CLOSING"},
		{"udp", 1, "ESTAB"},
		{"udp", 7, "UNCONN"},
		{"udp", 0, "UNCONN"},
	}
	for _, c := range cases {
		if got := StateWord(c.netid, c.state); got != c.want {
			t.Errorf("StateWord(%s, %d) = %q, want %q", c.netid, c.state, got, c.want)
		}
	}
}

func TestEndpoint(t *testing.T) {
	cases := []struct {
		ip   string
		port uint16
		want string
	}{
		{"0.0.0.0", 22, "0.0.0.0:22"},
		{"0.0.0.0", 0, "0.0.0.0:*"},
		{"127.0.0.53", 53, "127.0.0.53:53"},
		{"::", 22, "[::]:22"},
		{"::1", 631, "[::1]:631"},
	}
	for _, c := range cases {
		if got := Endpoint(net.ParseIP(c.ip), c.port); got != c.want {
			t.Errorf("Endpoint(%s, %d) = %q, want %q", c.ip, c.port, got, c.want)
		}
	}
}

func TestSocketInode(t *testing.T) {
	cases := []struct {
		target string
		want   uint64
		ok     bool
	}{
		{"socket:[12345]", 12345, true},
		{"/dev/pts/0", 0, false},
		{"anon_inode:[eventpoll]", 0, false},
		{"socket:[abc]", 0, false},
		{"socket:[7", 0, false},
	}
	for _, c := range cases {
		got, ok := SocketInode(c.target)
		if got != c.want || ok != c.ok {
			t.Errorf("SocketInode(%q) = (%d, %v), want (%d, %v)", c.target, got, ok, c.want, c.ok)
		}
	}
}
