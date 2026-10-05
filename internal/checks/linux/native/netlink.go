// native_netlink: the socket table, addresses, neighbors, and routes taken
// from the kernel over rtnetlink and sock_diag, in place of ss/ip/ifconfig/arp.
// Those are dynamically linked userspace binaries whose output an LD_PRELOAD
// hook or a PATH shadow can reshape; the kernel's own netlink dump cannot be
// reached that way. This file holds the row shapes and the renderers, so the
// formatting is testable off Linux; the netlink calls are in
// native_netlink_linux.go.
//
// One field netlink does not carry is which process holds a socket, so
// /proc/[pid]/fd is walked for the inode-to-process map, the same step ss -p
// performs.

package native

import (
	"cmp"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
)

// ssRow is one socket-table row: the columns `ss -tunap` prints. The local cell
// carries ss's "%ifname" suffix when the socket is bound to a device, since the
// interface only belongs to the local side of the pair.
type ssRow struct {
	netid string // "tcp" or "udp"
	state string // ss's state word
	rq    uint32 // Recv-Q
	sq    uint32 // Send-Q
	local string // local address:port
	peer  string // peer address:port
	inode uint64 // the socket inode, the owner lookup key
}

// socketHolder is one (process, fd) pair holding a socket.
type socketHolder struct {
	comm string
	pid  int
	fd   int
}

// linkRow is one `ip -br addr` row.
type linkRow struct {
	name  string
	state string
	addrs []string
}

// neighRow is one `ip neigh` row.
type neighRow struct {
	ip     string
	dev    string
	lladdr string
	flags  []string // router, proxy, managed, extern_learn, offload, extern_valid
	state  string   // the NUD state words, empty when the kernel reports none
}

// routeRow is one `ip route` row.
type routeRow struct {
	dest   string
	via    string
	dev    string
	proto  string
	scope  string
	src    string
	metric int
}

const (
	// ssHeader is fixed-width so the listen lexer, which anchors on
	// `^Netid\s+State\s`, reads the native table exactly as it reads ss.
	ssHeader = "Netid State   Recv-Q Send-Q Local Address:Port   Peer Address:Port   Process\n"
	ssRowFmt = "%-5s %-6s %6d %6d %-20s %-20s %s\n"
)

// tcpStateWord maps the kernel's TCP state number to the word ss prints.
var tcpStateWord = map[uint8]string{
	1:  "ESTAB",
	2:  "SYN-SENT",
	3:  "SYN-RECV",
	4:  "FIN-WAIT-1",
	5:  "FIN-WAIT-2",
	6:  "TIME-WAIT",
	7:  "CLOSE",
	8:  "CLOSE-WAIT",
	9:  "LAST-ACK",
	10: "LISTEN",
	11: "CLOSING",
	12: "NEW-SYN-RECV",
}

// ssStateWord spells one socket's state. UDP is connectionless: the kernel
// reports TCP_CLOSE(7) for an unconnected socket, which ss prints UNCONN.
func ssStateWord(netid string, state uint8) string {
	if netid == "udp" {
		if state == 1 {
			return "ESTAB"
		}
		return "UNCONN"
	}
	if word, ok := tcpStateWord[state]; ok {
		return word
	}
	return strconv.Itoa(int(state))
}

// ssEndpoint renders ss's address:port cell; port 0 (an unconnected peer)
// prints "*", a v6 address is bracketed, and a socket bound to a device carries
// ss's "%ifname" between the address and the port.
func ssEndpoint(ip net.IP, port uint16, ifname string) string {
	host := ip.String()
	if ip.To4() == nil {
		host = "[" + host + "]"
	}
	if ifname != "" {
		host += "%" + ifname
	}
	if port == 0 {
		return host + ":*"
	}
	return host + ":" + strconv.Itoa(int(port))
}

// ssProcess renders ss's Process column: the users:((name,pid,fd)) list, empty
// when no local process was found for the socket.
func ssProcess(holders []socketHolder) string {
	if len(holders) == 0 {
		return ""
	}
	sorted := slices.Clone(holders)
	slices.SortFunc(sorted, func(a, b socketHolder) int {
		return cmp.Or(cmp.Compare(a.pid, b.pid), cmp.Compare(a.fd, b.fd))
	})
	parts := make([]string, 0, len(sorted))
	for _, h := range sorted {
		parts = append(parts, fmt.Sprintf("(\"%s\",pid=%d,fd=%d)", h.comm, h.pid, h.fd))
	}
	return "users:(" + strings.Join(parts, ",") + ")"
}

// renderSs builds the socket table: header, then one row per socket ordered by
// netid, local endpoint, and peer so two collections of a host diff cleanly.
func renderSs(rows []ssRow, holders map[uint64][]socketHolder) string {
	sorted := slices.Clone(rows)
	slices.SortStableFunc(sorted, func(a, b ssRow) int {
		return cmp.Or(strings.Compare(a.netid, b.netid), strings.Compare(a.local, b.local), strings.Compare(a.peer, b.peer))
	})
	var b strings.Builder
	b.WriteString(ssHeader)
	for _, r := range sorted {
		fmt.Fprintf(&b, ssRowFmt, r.netid, r.state, r.rq, r.sq, r.local, r.peer, ssProcess(holders[r.inode]))
	}
	return b.String()
}

// renderLinkRows prints `ip -br addr` rows: the interface, the operational
// state, then the addresses.
func renderLinkRows(rows []linkRow) string {
	var b strings.Builder
	for _, r := range rows {
		if len(r.addrs) == 0 {
			fmt.Fprintf(&b, "%-16s %s\n", r.name, r.state)
			continue
		}
		fmt.Fprintf(&b, "%-16s %-15s %s\n", r.name, r.state, strings.Join(r.addrs, " "))
	}
	return b.String()
}

// renderNeighRows prints `ip neigh` rows: address, device, link-layer address,
// the flags ip prints as bare words, then the state words.
func renderNeighRows(rows []neighRow) string {
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(r.ip + " dev " + r.dev)
		if r.lladdr != "" {
			b.WriteString(" lladdr " + r.lladdr)
		}
		for _, flag := range r.flags {
			b.WriteString(" " + flag)
		}
		if r.state != "" {
			b.WriteString(" " + r.state)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// renderRouteRows prints `ip route` rows in the field order ip uses.
func renderRouteRows(rows []routeRow) string {
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(r.dest)
		if r.via != "" {
			b.WriteString(" via " + r.via)
		}
		if r.dev != "" {
			b.WriteString(" dev " + r.dev)
		}
		if r.proto != "" {
			b.WriteString(" proto " + r.proto)
		}
		if r.scope != "" {
			b.WriteString(" scope " + r.scope)
		}
		if r.src != "" {
			b.WriteString(" src " + r.src)
		}
		if r.metric != 0 {
			fmt.Fprintf(&b, " metric %d", r.metric)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// routeDest is ip route's destination cell: the prefix, or "default" for the
// zero-length mask. A full-length mask is a host route, and ip prints the bare
// address without the /32 or /128.
func routeDest(dst *net.IPNet) string {
	if dst == nil {
		return "default"
	}
	ones, bits := dst.Mask.Size()
	if ones == 0 && bits != 0 {
		return "default"
	}
	if ones == bits {
		return dst.IP.String()
	}
	return dst.String()
}

// neighStateWords spells a neighbor entry's state the way ip neigh does: every
// set bit as a word, in the order iproute2 prints them, joined by blanks. An
// entry the kernel reports without a NUD state yields no words at all.
var neighStateOrder = []struct {
	bit  int
	word string
}{
	{0x01, "INCOMPLETE"},
	{0x02, "REACHABLE"},
	{0x04, "STALE"},
	{0x08, "DELAY"},
	{0x10, "PROBE"},
	{0x20, "FAILED"},
	{0x40, "NOARP"},
	{0x80, "PERMANENT"},
}

func neighStateWords(state int) string {
	if state == 0 {
		return ""
	}
	words := make([]string, 0, 2)
	for _, entry := range neighStateOrder {
		if state&entry.bit != 0 {
			words = append(words, entry.word)
		}
	}
	if len(words) == 0 {
		return strconv.Itoa(state)
	}
	return strings.Join(words, " ")
}

// neighVisible is ip neigh's default state filter (0xFF & ~NUD_NOARP): an entry
// whose state is NOARP alone — a no-ARP-needed pseudo entry — is not shown, and
// neither is one the kernel reports without any state. The proxy and
// extern_learn flags keep an entry visible regardless.
func neighVisible(state, flags int) bool {
	const (
		nudNoarp  = 0x40
		ntfProxy  = 0x08
		ntfExtLrn = 0x10
	)
	if flags&(ntfProxy|ntfExtLrn) != 0 {
		return true
	}
	return state&(0xff&^nudNoarp) != 0
}

// socketInode pulls the inode out of a /proc/[pid]/fd target of the form
// "socket:[123]".
func socketInode(target string) (uint64, bool) {
	rest, found := strings.CutPrefix(target, "socket:[")
	if !found || !strings.HasSuffix(rest, "]") {
		return 0, false
	}
	inode, err := strconv.ParseUint(strings.TrimSuffix(rest, "]"), 10, 64)
	return inode, err == nil
}
