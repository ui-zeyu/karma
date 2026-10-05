//go:build linux

package linux

import (
	"context"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"karma/internal/model"
)

// nativeSs reads the socket table the way `ss -tunap` does: the kernel's
// sock_diag dump for the sockets themselves, then /proc for the owning process.
// Both address families and both protocols are dumped; a family whose dump is
// refused is skipped, and only when every dump fails does the tier report
// itself unavailable so the shell ladder answers.
func nativeSs(ctx context.Context) (string, error) {
	sources := []struct {
		netid string
		diag  func(uint8) ([]*netlink.Socket, error)
	}{
		{"tcp", netlink.SocketDiagTCP},
		{"udp", netlink.SocketDiagUDP},
	}
	var rows []ssRow
	answered := false
	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		for _, src := range sources {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			socks, err := src.diag(family)
			if err != nil {
				continue
			}
			answered = true
			for _, s := range socks {
				rows = append(rows, ssRow{
					netid: src.netid,
					state: ssStateWord(src.netid, s.State),
					rq:    s.RQueue,
					sq:    s.WQueue,
					local: ssEndpoint(s.ID.Source, s.ID.SourcePort),
					peer:  ssEndpoint(s.ID.Destination, s.ID.DestinationPort),
					inode: uint64(s.INode),
				})
			}
		}
	}
	if !answered {
		return "", model.ErrTierUnavailable
	}
	inodes := make(map[uint64]bool, len(rows))
	for _, r := range rows {
		if r.inode != 0 {
			inodes[r.inode] = true
		}
	}
	return renderSs(rows, socketHolders(inodes)), nil
}

// socketHolders maps each socket inode to the processes holding it, by walking
// /proc/[pid]/fd for "socket:[inode]" links. Reading another user's fd
// directory needs root, so a non-root run attributes only its own sockets, the
// same limit `ss -p` has.
func socketHolders(inodes map[uint64]bool) map[uint64][]socketHolder {
	out := map[uint64][]socketHolder{}
	if len(inodes) == 0 {
		return out
	}
	procs, err := procFS().AllProcs()
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
			inode, ok := socketInode(target)
			if !ok || !inodes[inode] || i >= len(fds) {
				continue
			}
			out[inode] = append(out[inode], socketHolder{comm: comm, pid: p.PID, fd: int(fds[i])})
		}
	}
	return out
}

// nativeIPAddr reads the address table the way `ip -br addr` prints it.
func nativeIPAddr(ctx context.Context) (string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return "", model.ErrTierUnavailable
	}
	rows := make([]linkRow, 0, len(links))
	for _, l := range links {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		attrs := l.Attrs()
		addrs, err := netlink.AddrList(l, unix.AF_UNSPEC)
		if err != nil {
			return "", model.ErrTierUnavailable
		}
		row := linkRow{name: attrs.Name, state: strings.ToUpper(attrs.OperState.String())}
		for _, a := range addrs {
			if a.IPNet != nil {
				row.addrs = append(row.addrs, a.IPNet.String())
			}
		}
		rows = append(rows, row)
	}
	return renderLinkRows(rows), nil
}

// nativeIPNeigh reads the neighbor table the way `ip neigh` prints it.
func nativeIPNeigh(ctx context.Context) (string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return "", model.ErrTierUnavailable
	}
	dev := map[int]string{}
	for _, l := range links {
		dev[l.Attrs().Index] = l.Attrs().Name
	}
	var rows []neighRow
	answered := false
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		neighs, err := netlink.NeighList(0, family)
		if err != nil {
			continue
		}
		answered = true
		for _, n := range neighs {
			name := dev[n.LinkIndex]
			if name == "" || n.IP == nil {
				continue
			}
			row := neighRow{ip: n.IP.String(), dev: name, state: neighState(n.State)}
			if len(n.HardwareAddr) > 0 {
				row.lladdr = n.HardwareAddr.String()
			}
			rows = append(rows, row)
		}
	}
	if !answered {
		return "", model.ErrTierUnavailable
	}
	return renderNeighRows(rows), nil
}

// nativeIPRoute reads the routing table the way `ip route` prints it.
func nativeIPRoute(ctx context.Context) (string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return "", model.ErrTierUnavailable
	}
	dev := map[int]string{}
	for _, l := range links {
		dev[l.Attrs().Index] = l.Attrs().Name
	}
	routes, err := netlink.RouteList(nil, unix.AF_UNSPEC)
	if err != nil {
		return "", model.ErrTierUnavailable
	}
	rows := make([]routeRow, 0, len(routes))
	for _, r := range routes {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		row := routeRow{
			dest:   routeDest(r.Dst),
			dev:    dev[r.LinkIndex],
			proto:  r.Protocol.String(),
			scope:  routeScope(r.Scope),
			metric: r.Priority,
		}
		if r.Gw != nil {
			row.via = r.Gw.String()
		}
		if r.Src != nil {
			row.src = r.Src.String()
		}
		rows = append(rows, row)
	}
	return renderRouteRows(rows), nil
}

// routeDest is ip route's destination cell: the prefix, or "default" for the
// zero-length mask.
func routeDest(dst *net.IPNet) string {
	if dst == nil {
		return "default"
	}
	if ones, bits := dst.Mask.Size(); ones == 0 && bits != 0 {
		return "default"
	}
	return dst.String()
}

// routeScope is ip route's scope cell, empty for universe: ip omits the
// default scope.
func routeScope(scope netlink.Scope) string {
	if scope == netlink.SCOPE_UNIVERSE {
		return ""
	}
	return scope.String()
}
