// native tiers of the network checks: the /proc socket tables and the
// iptables/ip6tables/nft layout.

package native

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/samber/lo"

	"karma/internal/localfs"
	"karma/internal/model"
	"karma/internal/section"
	"karma/internal/textutil"
)

// HostnameIps mirrors `hostname -I`: every interface address except
// loopback, gathered over netlink — no hostname binary, no NSS.
func HostnameIps(ctx context.Context) (string, error) {
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

// ProcNet mirrors the check's procNetScript: each /proc/net socket table it
// hands in becomes one section; ParseProcNet (the probe's Adapt) restores the
// hex endpoints.
func ProcNet(paths []string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return localfs.ReadSections(paths, nil), nil }
}

// Firewall mirrors the check's firewallScript: every family and table it hands
// in, then the nft ruleset — one section per surface, so rules cite what they
// fired on.
func Firewall(families, tables []string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var b strings.Builder
		for _, binary := range families {
			for _, table := range tables {
				b.WriteString(section.Line(binary + " " + table))
				b.WriteString(runHost(ctx, []string{binary, "-t", table, "-S"}, false).out)
			}
		}
		b.WriteString(section.Line("nft"))
		b.WriteString(runHost(ctx, []string{"nft", "list", "ruleset"}, false).out)
		return b.String(), nil
	}
}

// procNetStates: /proc/net state codes (uppercase hex). UDP state translation
// happens in native.ParseProcNet: the kernel marks a connectionless socket TCP_CLOSE(07),
// so a UDP section reads that code as UNCONN instead of the table's CLOSE.
var procNetStates = map[string]string{
	"00": "UNCONN",
	"01": "ESTAB",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

// decodeEndpoint restores a /proc/net hex address to ip:port (v4 dotted, v6 bracketed).
//
// v4 is one little-endian 32-bit word and v6 is four: reverse each word, keep word
// order. Reversing the whole thing would spell ::1 as a bogus address.
func decodeEndpoint(field string) (string, error) {
	addressHex, portHex, ok := strings.Cut(field, ":")
	if !ok {
		return "", fmt.Errorf("endpoint missing port: %s", field)
	}
	port, err := strconv.ParseUint(portHex, 16, 32)
	if err != nil {
		return "", err
	}
	raw, err := hex.DecodeString(addressHex)
	if err != nil {
		return "", err
	}
	if len(raw)%4 != 0 {
		return "", fmt.Errorf("address length is not a multiple of 4 bytes: %s", addressHex)
	}
	words := make([]byte, len(raw))
	for i := 0; i+4 <= len(raw); i += 4 {
		copy(words[i:], raw[i:i+4])
		slices.Reverse(words[i : i+4])
	}
	ip := net.IP(words).String()
	if len(words) == 4 {
		return ip + ":" + strconv.FormatUint(port, 10), nil
	}
	return "[" + ip + "]:" + strconv.FormatUint(port, 10), nil
}

// ParseProcNet converts one /proc/net/{tcp,tcp6,udp,udp6} section body into
// `state  local  remote` lines. The title differs TCP from UDP state semantics: in
// a UDP section both TCP_CLOSE(07) and the 00 placeholder translate to UNCONN as
// connectionless.
func ParseProcNet(title string, text string) *model.Shaped {
	udp := strings.Contains(title, "/udp")
	lines := lo.FilterMap(textutil.CollectLines(text), func(row string, _ int) (string, bool) {
		fields := strings.Fields(row)
		if len(fields) < 4 || strings.TrimSuffix(fields[0], ":") == "sl" {
			return "", false
		}
		local, err := decodeEndpoint(fields[1])
		if err != nil {
			return "", false
		}
		remote, err := decodeEndpoint(fields[2])
		if err != nil {
			return "", false
		}
		// A UDP socket is connectionless: the kernel reports TCP_CLOSE(07) for it,
		// so the TCP table would print CLOSE; the section says UDP, so the state
		// reads UNCONN.
		state := strings.ToUpper(fields[3])
		if udp && (state == "00" || state == "07") {
			state = "UNCONN"
		} else if mapped, ok := procNetStates[state]; ok {
			state = mapped
		}
		return state + "  " + local + "  " + remote, true
	})
	return &model.Shaped{Text: strings.Join(lines, "\n")}
}
