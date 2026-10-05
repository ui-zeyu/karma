// network: sockets, addresses, routes, neighbors, firewall, hosts and resolv.
//
// The listen check's last fallback parses /proc/net/* directly, covering minimal
// containers where both ss and netstat are missing.

package linux

import (
	"karma/internal/checks/linux/native"
	"karma/internal/define"
	"karma/internal/model"
	"karma/internal/script"
	"strings"
)

// procNetScript: each of the four files becomes a section (ReadFiles' `== path`
// header): native.ParseProcNet uses the adapt section-title parameter to tell TCP from UDP
// state semantics, which a plain cat merge cannot distinguish.
// procNetPaths are the four socket tables the check renders, one section each.
var procNetPaths = []string{"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"}

var procNetScript = script.ReadFiles(procNetPaths, `cat "$f"`, true)

// firewallScript: `-S` alone only shows the filter table, leaving out nat/mangle/raw
// and IPv6; one script lays out every surface and adds the nft ruleset (when the
// iptables compat layer is present it is not skipped by the fallback either).
// firewallFamilies and firewallTables are the surfaces the firewall check
// covers; one loop per family, then the nft ruleset.
var (
	firewallFamilies = []string{"iptables", "ip6tables"}
	firewallTables   = []string{"filter", "nat", "mangle", "raw"}
)

// firewallScript is that shape as the ssh script.
var firewallScript = firewallScriptText()

func firewallScriptText() string {
	var b strings.Builder
	for _, binary := range firewallFamilies {
		b.WriteString("for t in " + strings.Join(firewallTables, " ") + "; do\n")
		b.WriteString("  echo \"== " + binary + " $t\"\n")
		b.WriteString("  " + binary + " -t \"$t\" -S 2>/dev/null\n")
		b.WriteString("done\n")
	}
	b.WriteString("echo \"== nft\"\nnft list ruleset 2>/dev/null\n")
	return b.String()
}

// NetworkChecks covers networking.
var NetworkChecks = []*model.Check{
	define.LinuxCheck("listen", "Listening and established connections", model.AspectNetwork,
		[]model.Probe{
			{Label: "ss", Inv: model.Dual{Run: native.Ss, Script: "ss -tunap"}},
			{Label: "netstat", Inv: model.NewCommand("netstat", "-tunap")},
			// The proc-net hex address restore is this probe's own dialect (adapt carries the
			// section title to tell TCP/UDP); ss and netstat already output the target shape.
			{Label: "proc-net", Inv: model.Dual{
				Run:    native.ProcNet(procNetPaths),
				Script: procNetScript,
			}, Adapt: native.ParseProcNet},
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
			{Label: "ip", Inv: model.Dual{Run: native.IPAddr, Script: "ip -br addr"}},
			{Label: "ifconfig", Inv: model.NewCommand("ifconfig", "-a")},
			{Label: "hostname", Inv: model.Dual{Run: native.HostnameIps, Script: "hostname -I"}},
		},
		define.CheckOpt{Syntax: "ip-addr"}),
	define.LinuxCheck("arp", "ARP / neighbor table", model.AspectNetwork,
		[]model.Probe{
			{Label: "ip", Inv: model.Dual{Run: native.IPNeigh, Script: "ip neigh"}},
			{Label: "arp", Inv: model.NewCommand("arp", "-n")},
		},
		define.CheckOpt{Syntax: "ip-keyval"}),
	define.LinuxCheck("route", "Routing table", model.AspectNetwork,
		[]model.Probe{
			{Label: "ip", Inv: model.Dual{Run: native.IPRoute, Script: "ip route"}},
			{Label: "route", Inv: model.NewCommand("route", "-n")},
			{Label: "netstat", Inv: model.NewCommand("netstat", "-rn")},
		},
		define.CheckOpt{Syntax: "ip-keyval"}),
	define.LinuxCheck("firewall", "Firewall rules", model.AspectNetwork,
		[]model.Probe{
			{Label: "iptables", Inv: model.Dual{
				Run:    native.Firewall(firewallFamilies, firewallTables),
				Script: firewallScript,
			}},
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
		readFilesCheck("/etc/hosts.allow", "/etc/hosts.deny"),
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("wrappers-exec", `\b(?:spawn|twist)\b`, model.High,
					"command runs on match (backdoor vector)"),
				model.NewRule("wrappers-active", `^[^#\s][^:]*:`, model.Medium,
					"access-control rule active"),
			},
		}),
	define.LinuxCheck("hosts-file", "hosts and DNS config", model.AspectNetwork,
		readFilesCheck("/etc/hosts", "/etc/resolv.conf"),
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
