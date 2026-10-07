//go:build linux

package native

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"karma/internal/model"
)

// Ss reads the socket table the way `ss -tunap` does: the kernel's
// sock_diag dump for the sockets themselves, then /proc for the owning process.
// Both address families and both protocols are dumped; a family whose dump is
// refused is skipped, and only when every dump fails does the tier report
// itself unavailable, so the check's next tier answers.
func Ss(ctx context.Context) (string, error) {
	sources := []struct {
		netid string
		diag  func(uint8) ([]*netlink.Socket, error)
	}{
		{"tcp", netlink.SocketDiagTCP},
		{"udp", netlink.SocketDiagUDP},
	}
	var rows []ssRow
	answered := false
	names := linkNames()
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
					local: ssEndpoint(s.ID.Source, s.ID.SourcePort, names[int(s.ID.Interface)]),
					peer:  ssEndpoint(s.ID.Destination, s.ID.DestinationPort, ""),
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

// IPAddr reads the address table the way `ip -br addr` prints it.
func IPAddr(ctx context.Context) (string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return "", model.ErrTierUnavailable
	}
	metrics := addrMetrics()
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
			if a.IPNet == nil {
				continue
			}
			cell := a.IPNet.String()
			// ip prints an address metric after the prefix; the library's Addr
			// carries no metric, so it comes from the separately parsed dump
			if metric := metrics[addrMetricKey(attrs.Index, a.IPNet)]; metric > 0 {
				cell += fmt.Sprintf(" metric %d", metric)
			}
			row.addrs = append(row.addrs, cell)
		}
		rows = append(rows, row)
	}
	return renderLinkRows(rows), nil
}

// ifaRtPriority is IFA_RT_PRIORITY, the address metric ip -br addr prints as
// "metric N" (uapi/linux/if_addr.h); netlink's Addr has no field for it.
const ifaRtPriority = 9

// addrMetricKey identifies one address row of the kernel's dump.
func addrMetricKey(linkIndex int, ipnet *net.IPNet) string {
	return fmt.Sprintf("%d|%s", linkIndex, ipnet)
}

// addrMetrics parses IFA_RT_PRIORITY out of an address dump: the kernel sends
// the metric as a separate attribute of the address message, and only
// addresses whose prefix route carries a priority have one (cloud images set
// 100 on their primary address).
func addrMetrics() map[string]int {
	req := nl.NewNetlinkRequest(unix.RTM_GETADDR, unix.NLM_F_DUMP)
	req.AddData(nl.NewIfAddrmsg(unix.AF_UNSPEC))
	msgs, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWADDR)
	if err != nil {
		return nil
	}
	out := map[string]int{}
	for _, msg := range msgs {
		header := nl.DeserializeIfAddrmsg(msg)
		attrs, err := nl.ParseRouteAttr(msg[header.Len():])
		if err != nil {
			continue
		}
		var (
			local  net.IP
			metric int
		)
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case unix.IFA_LOCAL, unix.IFA_ADDRESS:
				if local == nil {
					local = net.IP(attr.Value)
				}
			case ifaRtPriority:
				if len(attr.Value) >= 4 {
					metric = int(binary.LittleEndian.Uint32(attr.Value[:4]))
				}
			}
		}
		if local == nil || metric == 0 {
			continue
		}
		ipnet := &net.IPNet{
			IP:   local,
			Mask: net.CIDRMask(int(header.Prefixlen), len(local)*8),
		}
		out[addrMetricKey(int(header.Index), ipnet)] = metric
	}
	return out
}

// linkNames maps every interface index to its name, for the socket table's
// "%ifname" suffix and the neighbor rows' dev column.
func linkNames() map[int]string {
	links, err := netlink.LinkList()
	if err != nil {
		return nil
	}
	names := make(map[int]string, len(links))
	for _, l := range links {
		names[l.Attrs().Index] = l.Attrs().Name
	}
	return names
}

// IPNeigh reads the neighbor table the way `ip neigh` prints it: the
// entries ip's default state filter keeps (no NOARP-only pseudo entries, no
// stateless ones), with the flags ip prints as bare words.
func IPNeigh(ctx context.Context) (string, error) {
	dev := linkNames()
	if dev == nil {
		return "", model.ErrTierUnavailable
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
			if name == "" || n.IP == nil || !neighVisible(n.State, n.Flags) {
				continue
			}
			row := neighRow{ip: n.IP.String(), dev: name, state: neighStateWords(n.State)}
			if len(n.HardwareAddr) > 0 {
				row.lladdr = n.HardwareAddr.String()
			}
			row.flags = neighFlags(n.Flags, n.FlagsExt)
			rows = append(rows, row)
		}
	}
	if !answered {
		return "", model.ErrTierUnavailable
	}
	return renderNeighRows(rows), nil
}

// NTF_EXT_* live in the kernel's extended-flags attribute (NDA_FLAGS_EXT); the
// netlink package carries only NTF_EXT_MANAGED, so the rest are spelled here
// (uapi/linux/neighbour.h).
const (
	ntfExtManaged      = 0x1
	ntfExtExtValidated = 0x4
)

// neighFlags spells the neighbor flags ip neigh prints, in iproute2's order:
// the plain ndm_flags words first, "managed" and "extern_valid" (the extended
// attribute) in the positions ip uses.
func neighFlags(flags, extFlags int) []string {
	var out []string
	if flags&netlink.NTF_ROUTER != 0 {
		out = append(out, "router")
	}
	if flags&netlink.NTF_PROXY != 0 {
		out = append(out, "proxy")
	}
	if extFlags&ntfExtManaged != 0 {
		out = append(out, "managed")
	}
	if flags&netlink.NTF_EXT_LEARNED != 0 {
		out = append(out, "extern_learn")
	}
	if flags&netlink.NTF_OFFLOADED != 0 {
		out = append(out, "offload")
	}
	if extFlags&ntfExtExtValidated != 0 {
		out = append(out, "extern_valid")
	}
	return out
}

// IPRoute reads the routing table the way `ip route` prints it, both address
// families in the one dump. An IPv6 row can carry fields iproute2 reads from
// attributes the library's Route does not decode ("pref medium", a nexthop id,
// "expires Nsec"): the destination, the gateway, the device, and the protocol,
// scope, source and metric columns are the same, which is what the rows are
// read for.
func IPRoute(ctx context.Context) (string, error) {
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

// routeScope is ip route's scope cell, empty for universe: ip omits the
// default scope.
func routeScope(scope netlink.Scope) string {
	if scope == netlink.SCOPE_UNIVERSE {
		return ""
	}
	return scope.String()
}
