// network: sockets, addresses, routes, neighbors, firewall, hosts and resolv.
//
// The listen check's last fallback parses /proc/net/* directly, covering minimal
// containers where both ss and netstat are missing.

package linux

import (
	"encoding/hex"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/samber/lo"

	"karma/internal/define"
	"karma/internal/model"
	"karma/internal/script"
	"karma/internal/textutil"
)

// procNetScript: each of the four files becomes a section (ReadFiles' `== path`
// header): parseProcNet uses the adapt section-title parameter to tell TCP from UDP
// state semantics, which a plain cat merge cannot distinguish.
var procNetScript = script.ReadFiles([]string{
	"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6",
}, `cat "$f"`, true)

// firewallScript: `-S` alone only shows the filter table, leaving out nat/mangle/raw
// and IPv6; one script lays out every surface and adds the nft ruleset (when the
// iptables compat layer is present it is not skipped by the fallback either).
const firewallScript = `for t in filter nat mangle raw; do
  echo "== iptables $t"
  iptables -t "$t" -S 2>/dev/null
done
for t in filter nat mangle raw; do
  echo "== ip6tables $t"
  ip6tables -t "$t" -S 2>/dev/null
done
echo "== nft"
nft list ruleset 2>/dev/null
`

// procNetStates: /proc/net state codes (uppercase hex). UDP state translation
// happens in parseProcNet: the kernel marks a connectionless socket TCP_CLOSE(07),
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

// parseProcNet converts one /proc/net/{tcp,tcp6,udp,udp6} section body into
// `state  local  remote` lines. The title differs TCP from UDP state semantics: in
// a UDP section both TCP_CLOSE(07) and the 00 placeholder translate to UNCONN as
// connectionless.
func parseProcNet(title string, text string) *model.Shaped {
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

// NetworkChecks covers networking.
var NetworkChecks = []*model.Check{
	define.LinuxCheck("listen", "Listening and established connections", model.AspectNetwork,
		[]model.Probe{
			{Label: "ss", Inv: model.NewCommand("ss", "-tunap")},
			{Label: "netstat", Inv: model.NewCommand("netstat", "-tunap")},
			// The proc-net hex address restore is this probe's own dialect (adapt carries the
			// section title to tell TCP/UDP); ss and netstat already output the target shape.
			{Label: "proc-net", Inv: model.Shell{Script: procNetScript}, Adapt: parseProcNet},
		},
		define.CheckOpt{
			Syntax: "listen",
			Rules: []model.Rule{
				// Established connections are the normal-case listing (every SSH session is in
				// it), so making them always-printed findings would let --max-lines fail to bound
				// the connection table; the process holding the socket is the signal, lit by the
				// critical rules below. ESTABLISHED also covers the netstat probe.
				model.NewRule("net-established", `\bESTAB(?:LISHED)?\b`, model.Benign,
					"established connection"),
				// ss: users:(("bash",pid=..)); netstat: trailing pid/program column
				model.NewRule("net-interpreter-socket-ss",
					`\(\("[^"\n]*(?:sh|python[0-9.]*|perl|nc[^"\n]*|socat|php|ruby|busybox)"`,
					model.Critical, "interpreter holds a socket (reverse shell)"),
				model.NewRule("net-interpreter-socket-netstat",
					`\d+/(?:[^\s|]*sh|python[0-9.]*|perl|nc[^\s|]*|socat|php|ruby|busybox)(?:\s|$)`,
					model.Critical, "interpreter holds a socket (reverse shell)"),
			},
		}),
	define.LinuxCheck("addr", "Network addresses", model.AspectNetwork,
		[]model.Probe{
			{Label: "ip", Inv: model.NewCommand("ip", "-br", "addr")},
			{Label: "ifconfig", Inv: model.NewCommand("ifconfig", "-a")},
			{Label: "hostname", Inv: model.NewCommand("hostname", "-I")},
		},
		define.CheckOpt{Syntax: "ip-addr"}),
	define.LinuxCheck("arp", "ARP / neighbor table", model.AspectNetwork,
		[]model.Probe{
			{Label: "ip", Inv: model.NewCommand("ip", "neigh")},
			{Label: "arp", Inv: model.NewCommand("arp", "-n")},
		},
		define.CheckOpt{Syntax: "ip-keyval"}),
	define.LinuxCheck("route", "Routing table", model.AspectNetwork,
		[]model.Probe{
			{Label: "ip", Inv: model.NewCommand("ip", "route")},
			{Label: "route", Inv: model.NewCommand("route", "-n")},
			{Label: "netstat", Inv: model.NewCommand("netstat", "-rn")},
		},
		define.CheckOpt{Syntax: "ip-keyval"}),
	define.LinuxCheck("firewall", "Firewall rules", model.AspectNetwork,
		[]model.Probe{
			{Label: "iptables", Inv: model.Shell{Script: firewallScript}},
			{Label: "nft", Inv: model.NewCommand("nft", "list", "ruleset")},
		},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("firewall-active", `^-A `, model.Medium, "active firewall rule"),
			},
		}),
	// The spawn/twist options in hosts.allow/deny run a command on match, a classic
	// backdoor vector; on a default system both files are all comments, so even a live
	// line is worth a look.
	define.LinuxCheck("tcp-wrappers", "TCP Wrappers (hosts.allow/deny)", model.AspectNetwork,
		[]model.Probe{readFilesProbe("/etc/hosts.allow", "/etc/hosts.deny")},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("wrappers-exec", `\b(?:spawn|twist)\b`, model.High,
					"command runs on match (backdoor vector)"),
				model.NewRule("wrappers-active", `^[^#\s][^:]*:`, model.Medium,
					"access-control rule active"),
			},
		}),
	define.LinuxCheck("hosts-file", "hosts and DNS config", model.AspectNetwork,
		[]model.Probe{readFilesProbe("/etc/hosts", "/etc/resolv.conf")},
		define.CheckOpt{
			Rules: []model.Rule{
				// "maps to a non-loopback address" becomes an exclusion (RE2 has no lookahead)
				model.NewRule("hosts-nonlocal", `^\s*[0-9a-fA-F:.]+\s+\S`, model.Medium,
					"hosts maps a non-loopback address").
					WithExclude(`^\s*(?:127\.|::1|0\.0\.0\.0|fe|ff)`),
				define.KeywordRule,
			},
		}),
}
