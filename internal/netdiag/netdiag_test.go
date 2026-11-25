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
		ip     string
		port   uint16
		ifname string
		want   string
	}{
		{"0.0.0.0", 22, "", "0.0.0.0:22"},
		{"0.0.0.0", 0, "", "0.0.0.0:*"},
		{"127.0.0.53", 53, "", "127.0.0.53:53"},
		{"::", 22, "", "[::]:22"},
		{"::1", 631, "", "[::1]:631"},
		// ss appends the bound interface between the address and the port
		{"127.0.0.53", 53, "lo", "127.0.0.53%lo:53"},
		{"172.17.234.94", 68, "eth0", "172.17.234.94%eth0:68"},
		{"fe80::216:3eff:fe3a:2862", 546, "eth0", "[fe80::216:3eff:fe3a:2862]%eth0:546"},
		{"10.0.0.1", 0, "eth0", "10.0.0.1%eth0:*"},
	}
	for _, c := range cases {
		if got := Endpoint(net.ParseIP(c.ip), c.port, c.ifname); got != c.want {
			t.Errorf("Endpoint(%s, %d, %q) = %q, want %q", c.ip, c.port, c.ifname, got, c.want)
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
