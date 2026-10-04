// remote remote interaction: PuTTY sessions and host keys, RDP connection history.
package windows

import (
	"karma/internal/define"
	"karma/internal/model"
)

const puttyKey = `HKCU\Software\SimonTatham\PuTTY`
const rdpKey = `HKCU\Software\Microsoft\Terminal Server Client`

var puttyScript = RegQuery(puttyKey, true)
var rdpScript = RegQuery(rdpKey, true)

// Common remote-control tools in Chinese incident response: registry traces plus service list, two
// lines of evidence. Each fragment prints a section header only when it has output, so a missing key
// or no match leaves no ghost section.
var remoteCtrlScript = RegScript(
	RegQuery(`HKLM\SOFTWARE\Oray\SunLogin`, true),
	RegQuery(`HKLM\SOFTWARE\ToDesk`, true),
	RegQuery(`HKLM\SOFTWARE\TeamViewer`, true),
	`$o = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'sunlogin|todesk|rustdesk|teamviewer|gotohttp|vnc' } | ForEach-Object { $_.Name + '  ' + $_.Status }; if ($o) { '== services'; $o }`,
)

const remoteCtrlRegistry = `(?i)^HKLM\\SOFTWARE(?:\\WOW6432Node)?\\(?:Oray|ToDesk|TeamViewer)`
const remoteCtrlService = `(?i)\b(?:SunloginClient|ToDesk_Service|RustDesk|TeamViewer|gotohttp)\b`
const remoteVNCService = `(?i)\b[a-z0-9_]*vnc[a-z0-9_]*\b\s`

// RemoteChecks is the remote interaction aspect.
var RemoteChecks = []*model.Check{
	define.WindowsCheck("putty", "PuTTY Sessions and Host Keys", model.AspectRemote,
		[]model.Probe{
			PSProbe("reg", puttyScript),
			RegDirectProbe("reg-direct", puttyKey, true, ""),
		},
		define.CheckOpt{Syntax: "reg"}),
	define.WindowsCheck("rdp-history", "Remote Desktop Connection History (tsclient)", model.AspectRemote,
		[]model.Probe{
			PSProbe("reg", rdpScript),
			RegDirectProbe("reg-direct", rdpKey, true, ""),
		},
		define.CheckOpt{Syntax: "reg"}),
	define.WindowsCheck("remote-control", "Remote Control Software (Sunlogin/ToDesk/TeamViewer/RustDesk/VNC)", model.AspectRemote,
		[]model.Probe{PSProbe("reg", remoteCtrlScript)},
		define.CheckOpt{
			Syntax: "reg",
			Rules: []model.Rule{
				model.NewRule("remote-ctrl-registry", remoteCtrlRegistry, model.High,
					"remote control software registry traces"),
				model.NewRule("remote-ctrl-service", remoteCtrlService, model.High,
					"remote control service in running list"),
				model.NewRule("remote-vnc-service", remoteVNCService, model.Medium,
					"VNC service"),
				define.KeywordRule,
			},
		}),
}
