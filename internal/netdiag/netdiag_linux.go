//go:build linux

package netdiag

import (
	"context"

	"github.com/prometheus/procfs"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Snapshot dumps the socket table: both protocols over both address families.
// A family whose dump is refused is skipped, and only when every dump fails
// does the snapshot report ErrUnavailable, so a kernel with only one family
// still answers.
func Snapshot(ctx context.Context) ([]Socket, error) {
	sources := []struct {
		netid string
		diag  func(uint8) ([]*netlink.Socket, error)
	}{
		{"tcp", netlink.SocketDiagTCP},
		{"udp", netlink.SocketDiagUDP},
	}
	var out []Socket
	answered := false
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		for _, src := range sources {
			if ctx.Err() != nil {
				return out, ctx.Err()
			}
			socks, err := src.diag(family)
			if err != nil {
				continue
			}
			answered = true
			for _, s := range socks {
				out = append(out, Socket{
					Netid:     src.netid,
					State:     s.State,
					Family:    family,
					Local:     s.ID.Source,
					LocalPort: s.ID.SourcePort,
					Peer:      s.ID.Destination,
					PeerPort:  s.ID.DestinationPort,
					IfIndex:   int(s.ID.Interface),
					Inode:     uint64(s.INode),
					UID:       s.UID,
					RQueue:    s.RQueue,
					WQueue:    s.WQueue,
				})
			}
		}
	}
	if !answered {
		return nil, ErrUnavailable
	}
	return out, nil
}

// Owners maps each socket inode to the processes holding it, by walking
// /proc/[pid]/fd for "socket:[inode]" links. Reading another user's fd
// directory needs root, so a non-root run attributes only its own sockets, the
// same limit ss -p has.
func Owners(inodes map[uint64]bool) map[uint64][]Owner {
	out := map[uint64][]Owner{}
	if len(inodes) == 0 {
		return out
	}
	fs, err := procfs.NewDefaultFS()
	if err != nil {
		return out
	}
	procs, err := fs.AllProcs()
	if err != nil {
		return out
	}
	for _, p := range procs {
		fds, err := p.FileDescriptors()
		if err != nil {
			continue
		}
		targets, err := p.FileDescriptorTargets()
		if err != nil {
			continue
		}
		comm, _ := p.Comm()
		for i, target := range targets {
			inode, ok := SocketInode(target)
			if !ok || !inodes[inode] || i >= len(fds) {
				continue
			}
			out[inode] = append(out[inode], Owner{PID: p.PID, FD: int(fds[i]), Comm: comm})
		}
	}
	return out
}
