// network network surface: connections and ports, hosts file.
package windows

import (
	"karma/internal/define"
	"karma/internal/model"
)

// High-confidence remote-control/reverse-shell ports; common service ports like 8888 and 5555 are not listed, too many false positives.
const connEvilPort = `(?i):(?:4444|4445|31337|44444)\s+ESTABLISHED`

// Only a hosts mapping to a dotted domain counts as a hijack surface; the default 127.0.0.1 localhost has no dot and does not match.
const hostsMapRule = `(?i)^\s*[0-9A-Fa-f:.]+\s+\S+\.\S+(?:\s|$)`

const winHostsScript = `Get-Content 'C:\Windows\System32\drivers\etc\hosts' -ErrorAction SilentlyContinue`

// NetworkChecks is the network aspect.
var NetworkChecks = []*model.Check{
	define.WindowsCheck("connections", "Network Connections and Ports (netstat)", model.AspectNetwork,
		[]model.Probe{{Label: "netstat", Inv: model.NewCommand("netstat", "-ano")}},
		define.CheckOpt{
			Syntax: "netstat",
			Rules: []model.Rule{
				model.NewRule("conn-evil-port", connEvilPort, model.High,
					"connection to a common remote-control/reverse-shell port"),
				define.KeywordRule,
			},
		}),
	define.WindowsCheck("win-hosts", "Hosts File", model.AspectNetwork,
		[]model.Probe{PSProbe("type", winHostsScript)},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("hosts-map", hostsMapRule, model.Medium,
					"hosts forces domain resolution (hijack or emulation)"),
				define.KeywordRule,
			},
		}),
}
