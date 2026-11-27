package netdiag

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

// ErrUnavailable reports that no sock_diag dump could be taken: the kernel
// interface is missing or refused every address family. A caller that has a
// fallback treats it as "this source answered nothing".
var ErrUnavailable = errors.New("sock_diag unavailable")

// Socket is one row of the kernel's socket table.
type Socket struct {
	Netid     string // "tcp" or "udp"
	State     uint8  // the kernel's TCP state number
	Family    uint8
	Local     net.IP
	LocalPort uint16
	Peer      net.IP
	PeerPort  uint16
	Inode     uint64
	UID       uint32
}

// Owner is one process holding a socket.
type Owner struct {
	PID  int
	Comm string
}

// tcpStateWord is the kernel's TCP state number as ss prints it.
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

// StateWord spells one socket's state. UDP is connectionless: the kernel
// reports TCP_CLOSE(7) for an unconnected socket, which ss prints UNCONN.
func StateWord(netid string, state uint8) string {
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

// Endpoint renders one address:port cell the way ss does: port 0 prints "*",
// a v6 address is bracketed.
func Endpoint(ip net.IP, port uint16) string {
	host := ip.String()
	if ip.To4() == nil {
		host = "[" + host + "]"
	}
	if port == 0 {
		return host + ":*"
	}
	return host + ":" + strconv.Itoa(int(port))
}

// SocketInode reads a /proc/[pid]/fd target that names a socket. Every other
// target (a pipe, a file, an anon inode) is not a socket and reports false.
func SocketInode(target string) (uint64, bool) {
	const prefix = "socket:["
	if !strings.HasPrefix(target, prefix) || !strings.HasSuffix(target, "]") {
		return 0, false
	}
	inode, err := strconv.ParseUint(target[len(prefix):len(target)-1], 10, 64)
	if err != nil {
		return 0, false
	}
	return inode, true
}
