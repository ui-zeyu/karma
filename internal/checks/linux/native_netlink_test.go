// tests for the netlink tiers' pure parts: the ss state words and endpoints,
// the socket owner column, the address/neighbor/route renderers, and the
// /proc fd target parse.

package linux

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
		if got := ssEndpoint(net.ParseIP(c.ip), c.port); got != c.want {
			t.Errorf("ssEndpoint(%s, %d) = %q, want %q", c.ip, c.port, got, c.want)
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

func TestNeighState(t *testing.T) {
	cases := []struct {
		state int
		want  string
	}{
		{0x02, "REACHABLE"},
		{0x04, "STALE"},
		{0x80, "PERMANENT"},
		{0x42, "NOARP"}, // NOARP rides on top of a reachability state
	}
	for _, c := range cases {
		if got := neighState(c.state); got != c.want {
			t.Errorf("neighState(%#x) = %q, want %q", c.state, got, c.want)
		}
	}
}

func TestRenderLinkRows(t *testing.T) {
	out := renderLinkRows([]linkRow{
		{name: "lo", state: "UNKNOWN", addrs: []string{"127.0.0.1/8", "::1/128"}},
		{name: "eth0", state: "UP", addrs: []string{"10.0.0.5/24"}},
		{name: "tun0", state: "DOWN"},
	})
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 rows, got %d:\n%s", len(lines), out)
	}
	// the ip-addr lexer splits the interface from the state on a run of blanks
	if !strings.HasPrefix(lines[0], "lo") || !strings.Contains(lines[0], "  UNKNOWN") {
		t.Errorf("lo row = %q", lines[0])
	}
	if !strings.Contains(lines[0], "127.0.0.1/8 ::1/128") {
		t.Errorf("lo addresses = %q", lines[0])
	}
	if got := strings.Fields(lines[2]); len(got) != 2 || got[0] != "tun0" || got[1] != "DOWN" {
		t.Errorf("addressless row = %q", lines[2])
	}
}

func TestRenderNeighRows(t *testing.T) {
	out := renderNeighRows([]neighRow{
		{ip: "10.0.0.1", dev: "eth0", lladdr: "aa:bb:cc:dd:ee:ff", state: "REACHABLE"},
		{ip: "10.0.0.9", dev: "eth0", state: "FAILED"},
	})
	want := "10.0.0.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n10.0.0.9 dev eth0 FAILED\n"
	if out != want {
		t.Errorf("renderNeighRows = %q, want %q", out, want)
	}
}

func TestRenderRouteRows(t *testing.T) {
	out := renderRouteRows([]routeRow{
		{dest: "default", via: "10.0.0.1", dev: "eth0", proto: "dhcp", src: "10.0.0.5", metric: 100},
		{dest: "10.0.0.0/24", dev: "eth0", proto: "kernel", scope: "link", src: "10.0.0.5"},
	})
	want := "default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.5 metric 100\n" +
		"10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5\n"
	if out != want {
		t.Errorf("renderRouteRows = %q, want %q", out, want)
	}
}
