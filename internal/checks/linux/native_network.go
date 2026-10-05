// native tiers of the network checks: the /proc socket tables and the
// iptables/ip6tables/nft layout.

package linux

import (
	"context"
	"fmt"
	"net"
	"strings"

	"karma/internal/model"
)

// nativeHostnameIps mirrors `hostname -I`: every interface address except
// loopback, gathered over netlink — no hostname binary, no NSS.
func nativeHostnameIps(ctx context.Context) (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", model.ErrTierUnavailable
	}
	var ips []string
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			ips = append(ips, ipnet.IP.String())
		}
	}
	if len(ips) == 0 {
		return "", model.ErrTierUnavailable
	}
	return strings.Join(ips, " ") + "\n", nil
}

// nativeProcNet mirrors procNetScript: each /proc/net socket table becomes
// one section; parseProcNet (the probe's Adapt) restores the hex endpoints.
func nativeProcNet(ctx context.Context) (string, error) {
	return readSections([]string{
		"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6",
	}, nil), nil
}

// nativeFirewall mirrors firewallScript: every iptables family and table,
// then the nft ruleset — one section per surface, so rules cite what they
// fired on.
func nativeFirewall(ctx context.Context) (string, error) {
	var b strings.Builder
	for _, binary := range []string{"iptables", "ip6tables"} {
		for _, table := range []string{"filter", "nat", "mangle", "raw"} {
			fmt.Fprintf(&b, "== %s %s\n", binary, table)
			b.WriteString(runHost(ctx, []string{binary, "-t", table, "-S"}, false).out)
		}
	}
	b.WriteString("== nft\n")
	b.WriteString(runHost(ctx, []string{"nft", "list", "ruleset"}, false).out)
	return b.String(), nil
}
