// network: sockets, addresses, routes, neighbors, firewall, hosts and resolv.
//
// The listen check's last fallback parses /proc/net/* directly, covering minimal
// containers where both ss and netstat are missing.

package linux

import (
	"karma/internal/checks/linux/native"
	"karma/internal/define"
	"karma/internal/model"
	"karma/internal/shape"
)

// procNetPaths are the four socket tables the check renders, one section each,
// titled with the path: native.ParseProcNet reads the section title to tell TCP
// from UDP state semantics, which a merged body cannot distinguish. The tier's
// own adapt carries that reading, and every section keeps its own title.
var procNetPaths = []string{"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"}

// procNetTier is that list as a tier pair: the four tables read in process, and
// the same four through the target's own cat.
func procNetTier() []model.Step {
	return filesTier("proc-net", `cat "$f"`, nil, native.ParseProcNet, procNetPaths)
}

// routeScript is the sh source's route reading: the IPv4 table, then the IPv6
// one (the in-process tier dumps both families in one pass).
const routeScript = "ip route; ip -6 route 2>/dev/null"

// firewallFamilies and firewallTables are the surfaces the firewall check
// covers; `-S` alone only shows the filter table, leaving out nat/mangle/raw and
// IPv6.
var (
	firewallFamilies = []string{"iptables", "ip6tables"}
	firewallTables   = []string{"filter", "nat", "mangle", "raw"}
)

// firewallTier is the check's surfaces as a tier pair, one section each: every
// family and table pair, then the nft ruleset, which is a surface of its own on
// both sources (with the iptables compat layer present, that ruleset is not
// skipped by the fallback either). The section titles are the surfaces' own
// names. The check holds no command step of its own for nft: it would read the
// same ruleset, and unlike a surface — whose refusal is the tier being
// unavailable — it would put the tool's own refusal into the panel, so a
// non-root run would report a permission error instead of skipping quietly.
func firewallTier() []model.Step {
	parts := make([]surface, 0, len(firewallFamilies)*len(firewallTables)+1)
	for _, binary := range firewallFamilies {
		for _, table := range firewallTables {
			parts = append(parts, surface{
				Title:  binary + " " + table,
				Native: native.Host(binary, "-t", table, "-S"),
				Script: binary + " -t " + table + " -S 2>/dev/null",
			})
		}
	}
	parts = append(parts, surface{
		Title:  "nft",
		Native: native.Host("nft", "list", "ruleset"),
		Script: "nft list ruleset 2>/dev/null",
	})
	return surfacesTier("iptables", nil, parts)
}

// NetworkChecks covers networking.
var NetworkChecks = []*model.Check{
	define.LinuxCheck("listen", "Listening and established connections", model.AspectNetwork,
		append([]model.Step{
			{{Label: "ss", Inv: model.Native{Body: native.Ss}}},
			{{Label: "ss-sh", Inv: model.Sh("ss -tunap")}},
			{{Label: "netstat", Inv: model.NewCommand("netstat", "-tunap")}},
		}, procNetTier()...),
		model.Options{
			Syntax: model.SyntaxListen,
			Rules: []model.Matcher{
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
		[]model.Step{
			{{Label: "ip", Inv: model.Native{Body: native.IPAddr}}},
			{{Label: "ip-sh", Inv: model.Sh("ip -br addr")}},
			{{Label: "ifconfig", Inv: model.NewCommand("ifconfig", "-a")}},
			{{Label: "hostname", Inv: model.Native{Body: native.HostnameIps}}},
			{{Label: "hostname-sh", Inv: model.Sh("hostname -I")}},
		},
		model.Options{Syntax: model.SyntaxIPAddr}),
	define.LinuxCheck("arp", "ARP / neighbor table", model.AspectNetwork,
		[]model.Step{
			{{Label: "ip", Inv: model.Native{Body: native.IPNeigh}}},
			{{Label: "ip-sh", Inv: model.Sh("ip neigh")}},
			{{Label: "arp", Inv: model.NewCommand("arp", "-n")}},
		},
		// ip neigh writes key-value rows; the reading layer aligns them into
		// the table the panel shows (shape.NeighTable), and the arp -n fallback
		// prints its own aligned table, which the shaper declines.
		model.Options{Syntax: model.SyntaxTable, Normalize: shape.NeighTable}),
	// Both address families: ip route dumps IPv4 alone, and the local tier's
	// netlink dump covers both, so an IPv6 route — a C2's default route, a
	// tunnel's — would otherwise show on one source only. The IPv6 dump runs
	// second and its failure is silent: the IPv4 rows are already this tier's
	// answer, and a kernel without IPv6 leaves them untouched.
	define.LinuxCheck("route", "Routing table", model.AspectNetwork,
		[]model.Step{
			{{Label: "ip", Inv: model.Native{Body: native.IPRoute}}},
			{{Label: "ip-sh", Inv: model.Sh(routeScript)}},
			{{Label: "route", Inv: model.NewCommand("route", "-n")}},
			{{Label: "netstat", Inv: model.NewCommand("netstat", "-rn")}},
		},
		// As arp: the shaper aligns ip's own rows and declines the route(8)
		// and netstat tables, which come pre-aligned.
		model.Options{Syntax: model.SyntaxTable, Normalize: shape.RouteTable}),
	define.LinuxCheck("firewall", "Firewall rules", model.AspectNetwork,
		firewallTier(),
		model.Options{
			Rules: []model.Matcher{
				model.NewRule("firewall-active", `^-A `, model.Medium, "active firewall rule"),
			},
		}),
	// The spawn/twist options in hosts.allow/deny run a command on match, a classic
	// backdoor vector; on a default system both files are all comments, so even a live
	// line is worth a look.
	define.LinuxCheck("tcp-wrappers", "TCP Wrappers (hosts.allow/deny)", model.AspectNetwork,
		readFilesCheck("/etc/hosts.allow", "/etc/hosts.deny"),
		model.Options{
			Rules: []model.Matcher{
				model.NewRule("wrappers-exec", `\b(?:spawn|twist)\b`, model.High,
					"command runs on match (backdoor vector)"),
				model.NewRule("wrappers-active", `^[^#\s][^:]*:`, model.Medium,
					"access-control rule active"),
			},
		}),
	define.LinuxCheck("hosts-file", "hosts and DNS config", model.AspectNetwork,
		readFilesCheck("/etc/hosts", "/etc/resolv.conf"),
		model.Options{
			Rules: []model.Matcher{
				// "maps to a non-loopback address" becomes an exclusion (RE2 has no lookahead).
				// The span is the whole entry, names included and the trailing comment
				// left out: the span is what the panel paints. A comment-only row maps
				// nothing and is not a hit.
				model.NewRule("hosts-nonlocal", `^\s*[0-9a-fA-F:.]+\s+[^#\s](?:[^#\n]*[^#\s])?`, model.Medium,
					"hosts maps a non-loopback address").
					WithExclude(`^\s*(?:127\.|::1|0\.0\.0\.0|fe|ff)`),
				define.KeywordRule,
			},
		}),
}
