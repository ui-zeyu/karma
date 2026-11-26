package audit

import (
	"context"
	"sort"

	"karma/internal/netdiag"
)

// collectSockets reads the listening surface and the established connections.
// The owner is resolved through /proc, so a privileged run attributes more rows
// than an unprivileged one; a row without an owner is still listed. The
// outbound count answers per process how many established connections it
// holds, the context that turns a quiet image into a live one.
func collectSockets(ctx context.Context) ([]Socket, []Connection, map[int]int, []string) {
	dump, err := netdiag.Snapshot(ctx)
	if err != nil {
		return nil, nil, nil, []string{"socket table unavailable: " + err.Error()}
	}
	inodes, established := socketInodes(dump)
	return buildSocketRows(dump, netdiag.Owners(ctx, inodes), established, false)
}

// collectSocketsScoped answers the same table for an object graph's selected pids.
// It reads only those fd tables, so a one-service graph does not pay for the
// whole host's socket owners.
func collectSocketsScoped(ctx context.Context, pids map[int]bool) ([]Socket, []Connection, map[int]int, []string) {
	if len(pids) == 0 {
		return nil, nil, nil, nil
	}
	dump, err := netdiag.Snapshot(ctx)
	if err != nil {
		return nil, nil, nil, []string{"socket table unavailable: " + err.Error()}
	}
	inodes, established := socketInodes(dump)
	return buildSocketRows(dump, netdiag.OwnersFor(ctx, inodes, pids), established, true)
}

func socketInodes(dump []netdiag.Socket) (map[uint64]bool, map[uint64]bool) {
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
	return inodes, established
}

func buildSocketRows(dump []netdiag.Socket, owners map[uint64][]netdiag.Owner, established map[uint64]bool, scoped bool) ([]Socket, []Connection, map[int]int, []string) {
	outbound := map[int]int{}
	for inode := range established {
		for _, owner := range owners[inode] {
			outbound[owner.PID]++
		}
	}
	var sockets []Socket
	var connections []Connection
	for _, socket := range dump {
		held := owners[socket.Inode]
		if scoped && len(held) == 0 {
			continue
		}
		if listener(socket) {
			entry := Socket{
				Proto: socket.Netid,
				State: netdiag.StateWord(socket.Netid, socket.State),
				Local: netdiag.Endpoint(socket.Local, socket.LocalPort, ""),
				Peer:  netdiag.Endpoint(socket.Peer, socket.PeerPort, ""),
			}
			if len(held) > 0 {
				entry.PID = held[0].PID
				entry.Comm = held[0].Comm
			}
			sockets = append(sockets, entry)
			continue
		}
		if socket.Netid != "tcp" || socket.State != 1 {
			continue
		}
		connection := Connection{
			Proto: "tcp",
			Local: netdiag.Endpoint(socket.Local, socket.LocalPort, ""),
			Peer:  netdiag.Endpoint(socket.Peer, socket.PeerPort, ""),
		}
		for _, owner := range held {
			connection.PIDs = append(connection.PIDs, owner.PID)
		}
		if len(held) > 0 {
			connection.PID = held[0].PID
			connection.Comm = held[0].Comm
		}
		connections = append(connections, connection)
	}
	sortSockets(sockets)
	sortConnections(connections)
	return sockets, connections, outbound, nil
}

func listener(socket netdiag.Socket) bool {
	if socket.Netid == "tcp" {
		return socket.State == 10 // TCP_LISTEN
	}
	return true
}

func sortConnections(connections []Connection) {
	sort.Slice(connections, func(i, j int) bool {
		if connections[i].Peer != connections[j].Peer {
			return connections[i].Peer < connections[j].Peer
		}
		if connections[i].Local != connections[j].Local {
			return connections[i].Local < connections[j].Local
		}
		return connections[i].PID < connections[j].PID
	})
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
