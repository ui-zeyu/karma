// tests for the netlink tiers' pure parts: the ss state words and endpoints,
// the socket owner column, the address/neighbor/route renderers, and the
// /proc fd target parse.

package native

import (
	"net"
	"strings"
	"testing"
)

func TestSsStateWord(t *testing.T) {
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
		if got := ssStateWord(c.netid, c.state); got != c.want {
			t.Errorf("ssStateWord(%s, %d) = %q, want %q", c.netid, c.state, got, c.want)
		}
	}
}

func TestSsEndpoint(t *testing.T) {
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
		if got := ssEndpoint(net.ParseIP(c.ip), c.port, c.ifname); got != c.want {
			t.Errorf("ssEndpoint(%s, %d, %q) = %q, want %q", c.ip, c.port, c.ifname, got, c.want)
		}
	}
}

func TestSsProcess(t *testing.T) {
	if got := ssProcess(nil); got != "" {
		t.Errorf("ssProcess(nil) = %q, want empty", got)
	}
	if got, want := ssProcess([]socketHolder{{comm: "sshd", pid: 812, fd: 3}}),
		`users:(("sshd",pid=812,fd=3))`; got != want {
		t.Errorf("ssProcess = %q, want %q", got, want)
	}
	// holders arrive in walk order; the column is ordered by pid then fd
	if got, want := ssProcess([]socketHolder{
		{comm: "b", pid: 9, fd: 5}, {comm: "a", pid: 4, fd: 3},
	}), `users:(("a",pid=4,fd=3),("b",pid=9,fd=5))`; got != want {
		t.Errorf("ssProcess = %q, want %q", got, want)
	}
}

func TestRenderSs(t *testing.T) {
	rows := []ssRow{
		{netid: "tcp", state: "LISTEN", sq: 4096, local: "0.0.0.0:22", peer: "0.0.0.0:*", inode: 12345},
		{netid: "udp", state: "UNCONN", local: "127.0.0.53:53", peer: "0.0.0.0:*", inode: 999},
	}
	out := renderSs(rows, map[uint64][]socketHolder{12345: {{comm: "sshd", pid: 812, fd: 3}}})
	header, body, _ := strings.Cut(out, "\n")
	if !strings.HasPrefix(header, "Netid State ") {
		t.Fatalf("header = %q, want the ss anchor `Netid State`", header)
	}
	if !strings.Contains(body, `users:(("sshd",pid=812,fd=3))`) {
		t.Errorf("process column missing:\n%s", body)
	}
	// the socket with no local process prints no Process column
	if strings.Count(body, "users:(") != 1 {
		t.Errorf("want exactly one process column:\n%s", body)
	}
	// rows come out netid-ordered
	if strings.Index(body, "tcp") > strings.Index(body, "udp") {
		t.Errorf("rows not ordered by netid:\n%s", body)
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
		got, ok := socketInode(c.target)
		if got != c.want || ok != c.ok {
			t.Errorf("socketInode(%q) = (%d, %v), want (%d, %v)", c.target, got, ok, c.want, c.ok)
		}
	}
}

func TestNeighStateWords(t *testing.T) {
	cases := []struct {
		state int
		want  string
	}{
		{0x02, "REACHABLE"},
		{0x04, "STALE"},
		{0x80, "PERMANENT"},
		{0x42, "REACHABLE NOARP"}, // iproute2 prints every set bit, in its order
		{0x02 | 0x08, "REACHABLE DELAY"},
		{0, ""}, // a stateless entry prints no state at all
	}
	for _, c := range cases {
		if got := neighStateWords(c.state); got != c.want {
			t.Errorf("neighStateWords(%#x) = %q, want %q", c.state, got, c.want)
		}
	}
}

func TestNeighVisibleHidesNoarpOnly(t *testing.T) {
	cases := []struct {
		state, flags int
		want         bool
	}{
		{0x02, 0, true},    // REACHABLE
		{0x42, 0, true},    // NOARP on top of a state ip prints
		{0x40, 0, false},   // the NOARP-only pseudo entries ip hides
		{0, 0, false},      // no state yet: ip skips it too
		{0x40, 0x08, true}, // NTF_PROXY keeps the entry
		{0x40, 0x10, true}, // NTF_EXT_LEARNED keeps the entry
		{0x80, 0, true},    // PERMANENT
	}
	for _, c := range cases {
		if got := neighVisible(c.state, c.flags); got != c.want {
			t.Errorf("neighVisible(%#x, %#x) = %v, want %v", c.state, c.flags, got, c.want)
		}
	}
}

func TestRenderNeighRowsFlagsBeforeState(t *testing.T) {
	out := renderNeighRows([]neighRow{
		{ip: "fe80::1", dev: "eth0", lladdr: "ee:ff:ff:ff:ff:ff", flags: []string{"router"}, state: "STALE"},
		{ip: "10.0.0.1", dev: "eth0", lladdr: "aa:bb:cc:dd:ee:ff", state: "REACHABLE"},
		{ip: "10.0.0.2", dev: "eth0", flags: []string{"proxy"}},
	})
	want := []string{
		"fe80::1 dev eth0 lladdr ee:ff:ff:ff:ff:ff router STALE ",
		"10.0.0.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE ",
		"10.0.0.2 dev eth0 proxy ",
	}
	for i, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if line != want[i] {
			t.Errorf("neigh row %d = %q, want %q", i, line, want[i])
		}
	}
}

func TestRouteDestHostRoutes(t *testing.T) {
	_, host4, _ := net.ParseCIDR("10.0.0.5/32")
	_, net4, _ := net.ParseCIDR("10.0.0.0/24")
	_, host6, _ := net.ParseCIDR("fe80::1/128")
	cases := []struct {
		dst  *net.IPNet
		want string
	}{
		{nil, "default"},
		{&net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, "default"},
		{host4, "10.0.0.5"}, // ip route prints a host route without the /32
		{host6, "fe80::1"},
		{net4, "10.0.0.0/24"},
	}
	for _, c := range cases {
		if got := routeDest(c.dst); got != c.want {
			t.Errorf("routeDest(%v) = %q, want %q", c.dst, got, c.want)
		}
	}
}

func TestRenderLinkRows(t *testing.T) {
	out := renderLinkRows([]linkRow{
		{name: "lo", state: "UNKNOWN", addrs: []string{"127.0.0.1/8", "::1/128"}},
		{name: "eth0", state: "UP", addrs: []string{"10.0.0.5/24"}},
		{name: "tun0", state: "DOWN"},
	})
	want := "lo               UNKNOWN        127.0.0.1/8 ::1/128 \n" +
		"eth0             UP             10.0.0.5/24 \n" +
		"tun0             DOWN           \n"
	if out != want {
		t.Errorf("renderLinkRows = %q, want %q", out, want)
	}
}

func TestRenderNeighRows(t *testing.T) {
	out := renderNeighRows([]neighRow{
		{ip: "10.0.0.1", dev: "eth0", lladdr: "aa:bb:cc:dd:ee:ff", state: "REACHABLE"},
		{ip: "10.0.0.9", dev: "eth0", state: "FAILED"},
	})
	// iproute2 prints every cell with a trailing blank, so each row ends in one
	want := "10.0.0.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE \n10.0.0.9 dev eth0 FAILED \n"
	if out != want {
		t.Errorf("renderNeighRows = %q, want %q", out, want)
	}
}

func TestRenderRouteRows(t *testing.T) {
	out := renderRouteRows([]routeRow{
		{dest: "default", via: "10.0.0.1", dev: "eth0", proto: "dhcp", src: "10.0.0.5", metric: 100},
		{dest: "10.0.0.0/24", dev: "eth0", proto: "kernel", scope: "link", src: "10.0.0.5"},
	})
	want := "default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.5 metric 100 \n" +
		"10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5 \n"
	if out != want {
		t.Errorf("renderRouteRows = %q, want %q", out, want)
	}
}
