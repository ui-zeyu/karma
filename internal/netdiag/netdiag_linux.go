//go:build linux

package netdiag

import (
	"context"
	"os"
	"strconv"

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
					Inode:     uint64(s.INode),
					UID:       s.UID,
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
func Owners(ctx context.Context, inodes map[uint64]bool) map[uint64][]Owner {
	return owners(ctx, inodes, nil)
}

// OwnersFor is Owners restricted to a pid set: a profile that selected a unit
// or one process does not read every process's fd table.
func OwnersFor(ctx context.Context, inodes map[uint64]bool, pids map[int]bool) map[uint64][]Owner {
	if len(pids) == 0 {
		return map[uint64][]Owner{}
	}
	return owners(ctx, inodes, func(pid int) bool { return pids[pid] })
}

func owners(ctx context.Context, inodes map[uint64]bool, keep func(pid int) bool) map[uint64][]Owner {
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
		if ctx.Err() != nil {
			return out
		}
		if keep != nil && !keep(p.PID) {
			continue
		}
		targets := fdTable(p.PID)
		if len(targets) == 0 {
			continue
		}
		comm, _ := p.Comm()
		for _, target := range targets {
			inode, ok := SocketInode(target)
			if !ok || !inodes[inode] {
				continue
			}
			out[inode] = append(out[inode], Owner{PID: p.PID, Comm: comm})
		}
	}
	return out
}

// fdTable reads one process's descriptor table in a single pass: one ReadDir
// of /proc/[pid]/fd, then one Readlink per descriptor number. A process that
// is gone, or a table this user may not read, answers nil. Only the link
// targets matter to the owner walk; the descriptor numbers do not.
func fdTable(pid int) []string {
	dir := "/proc/" + strconv.Itoa(pid) + "/fd"
	names, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(names))
	for _, name := range names {
		target, err := os.Readlink(dir + "/" + name.Name())
		if err != nil {
			continue
		}
		out = append(out, target)
	}
	return out
}
