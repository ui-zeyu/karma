package audit

import (
	"context"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"karma/internal/netdiag"
)

// collectSockets reads the listening surface and the established connections.
// The owner is resolved through /proc, so a privileged run attributes more rows
// than an unprivileged one; a row without an owner is still listed. The
// outbound count answers per process how many established connections it
// holds, the context that turns a quiet image into a live one.
func collectSockets(ctx context.Context) ([]Socket, map[int]int, []string) {
	dump, err := netdiag.Snapshot(ctx)
	if err != nil {
		return nil, nil, []string{"socket table unavailable: " + err.Error()}
	}
	inodes := map[uint64]bool{}
	established := map[uint64]bool{}
	for _, socket := range dump {
		if listener(socket) {
			inodes[socket.Inode] = true
		}
		if socket.Netid == "tcp" && socket.State == 1 { // TCP_ESTABLISHED
			inodes[socket.Inode] = true
			established[socket.Inode] = true
		}
	}
	owners := netdiag.Owners(inodes)
	outbound := map[int]int{}
	for inode := range established {
		for _, owner := range owners[inode] {
			outbound[owner.PID]++
		}
	}
	var sockets []Socket
	for _, socket := range dump {
		if !listener(socket) {
			continue
		}
		entry := Socket{
			Proto: socket.Netid,
			State: netdiag.StateWord(socket.Netid, socket.State),
			Local: netdiag.Endpoint(socket.Local, socket.LocalPort, ""),
			Peer:  netdiag.Endpoint(socket.Peer, socket.PeerPort, ""),
		}
		if held := owners[socket.Inode]; len(held) > 0 {
			entry.PID = held[0].PID
			entry.Comm = held[0].Comm
		}
		sockets = append(sockets, entry)
	}
	sortSockets(sockets)
	return sockets, outbound, nil
}

func listener(socket netdiag.Socket) bool {
	if socket.Netid == "tcp" {
		return socket.State == 10 // TCP_LISTEN
	}
	return true
}

func sortSockets(sockets []Socket) {
	sort.Slice(sockets, func(i, j int) bool {
		left, right := sockets[i], sockets[j]
		if left.Proto != right.Proto {
			return left.Proto < right.Proto
		}
		if left.Local != right.Local {
			return left.Local < right.Local
		}
		return left.Peer < right.Peer
	})
}

var (
	ssPID  = regexp.MustCompile(`pid=(\d+)`)
	ssComm = regexp.MustCompile(`users:\(\("([^"]+)"`)
)

// parseSocketLine reads one `ss -H -lntup` row.
func parseSocketLine(line string) (Socket, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return Socket{}, false
	}
	entry := Socket{Proto: fields[0], State: fields[1]}
	rest := ""
	if len(fields) >= 6 {
		// ss's own row: state, recv-q, send-q, local, peer, then the process.
		entry.Local, entry.Peer = fields[4], fields[5]
		rest = strings.Join(fields[6:], " ")
	} else {
		// The /proc/net/* fallback: state, local, peer, uid.
		entry.Local, entry.Peer = fields[2], fields[3]
		rest = strings.Join(fields[4:], " ")
	}
	if match := ssPID.FindStringSubmatch(rest); match != nil {
		entry.PID, _ = strconv.Atoi(match[1])
	}
	if match := ssComm.FindStringSubmatch(rest); match != nil {
		entry.Comm = match[1]
	}
	return entry, true
}
