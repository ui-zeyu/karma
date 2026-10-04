// remote remote interaction: PuTTY sessions and host keys, RDP connection history.

package windows

import (
	"karma/internal/define"
	"karma/internal/model"
)

const puttyKey = `HKCU\Software\SimonTatham\PuTTY`
const rdpKey = `HKCU\Software\Microsoft\Terminal Server Client`

// Common remote-control tools in Chinese incident response: registry traces plus service list, two
// lines of evidence. Each fragment prints a section header only when it has output, so a missing key
// or no match leaves no ghost section.
var remoteCtrlServicesFragment = psSection("'services'",
	`Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'sunlogin|todesk|rustdesk|teamviewer|gotohttp|vnc' } | ForEach-Object { $_.Name + '  ' + $_.Status }`)

var remoteCtrlKeys = []RegKey{
	{Path: `HKLM\SOFTWARE\Oray\SunLogin`, Recurse: true, Label: "sunlogin"},
	{Path: `HKLM\SOFTWARE\ToDesk`, Recurse: true, Label: "todesk"},
	{Path: `HKLM\SOFTWARE\TeamViewer`, Recurse: true, Label: "teamviewer"},
}

const remoteCtrlRegistry = `(?i)^HKLM\\SOFTWARE(?:\\WOW6432Node)?\\(?:Oray|ToDesk|TeamViewer)`
const remoteCtrlService = `(?i)\b(?:SunloginClient|ToDesk_Service|RustDesk|TeamViewer|gotohttp)\b`
const remoteVNCService = `(?i)\b[a-z0-9_]*vnc[a-z0-9_]*\b\s`

// RemoteChecks is the remote interaction aspect.
var RemoteChecks = []*model.Check{
	RegCheck("putty", "PuTTY Sessions and Host Keys", model.AspectRemote,
		[]RegKey{{Path: puttyKey, Recurse: true, Label: "reg-direct"}},
		define.CheckOpt{Syntax: "reg"}),
	RegCheck("rdp-history", "Remote Desktop Connection History (tsclient)", model.AspectRemote,
		[]RegKey{{Path: rdpKey, Recurse: true, Label: "reg-direct"}},
		define.CheckOpt{Syntax: "reg"}),
	RegCheck("remote-control", "Remote Control Software (Sunlogin/ToDesk/TeamViewer/RustDesk/VNC)", model.AspectRemote,
		remoteCtrlKeys,
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
		},
		remoteCtrlServicesFragment),
}
