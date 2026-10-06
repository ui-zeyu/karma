// remote remote interaction: PuTTY sessions and host keys, RDP connection history, remote-control
// traces and the Sunlogin client's own logs.

package windows

import (
	"strconv"

	"karma/internal/define"
	"karma/internal/model"
	"karma/internal/script"
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

// The Sunlogin client (向日葵) writes what it served into its own log — every accepted connection
// and the HTTP path of every request — and keeps its access code in config.ini next to it. The
// 2022 exploit chain is visible there: /cgi-bin/rpc?action=verify-haras reads the verify string,
// then /check?cmd=… runs a command as the client's user, which is the strongest evidence a
// remote-control host leaves behind after the fact.
const sunloginRoots = `'C:\Program Files\Oray\SunLogin\SunloginClient','C:\Program Files (x86)\Oray\SunLogin\SunloginClient'`

// The log files are rotated by the client and grow without bound, so each is read from its tail and
// the panel keeps only the lines that carry a fact.
const sunloginTail = 2000

var sunloginScript = script.Lines(
	"foreach ($f in Get-ChildItem "+sunloginRoots+" -Filter 'config.ini' -ErrorAction SilentlyContinue) {",
	"  "+psSection(`"== " + $f.FullName`, "Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue"),
	"}",
	"foreach ($f in Get-ChildItem "+sunloginRoots+" -Filter '*.log' -Recurse -ErrorAction SilentlyContinue) {",
	"  "+psSection(`"== " + $f.FullName`,
		"Get-Content -LiteralPath $f.FullName -Tail "+strconv.Itoa(sunloginTail)+" -ErrorAction SilentlyContinue"),
	"}",
)

// sunloginKeep is the allowlist the panel reads the log through: the client's own acceptor and
// request lines, and the config keys that say who can reach it.
const sunloginKeep = `(?i)(\[Acceptor\]|new acceptor|path:\s*/|encry_pwd|no_window_user_pwd|installautorun|logpath)`

// RemoteChecks is the remote interaction aspect.
var RemoteChecks = []*model.Check{
	RegCheck("putty", "PuTTY Sessions and Host Keys", model.AspectRemote,
		[]RegKey{{Path: puttyKey, Recurse: true, Label: "reg-direct"}},
		define.CheckOpt{Syntax: model.SyntaxReg}),
	RegCheck("rdp-history", "Remote Desktop Connection History (tsclient)", model.AspectRemote,
		[]RegKey{{Path: rdpKey, Recurse: true, Label: "reg-direct"}},
		define.CheckOpt{Syntax: model.SyntaxReg}),
	RegCheck("remote-control", "Remote Control Software (Sunlogin/ToDesk/TeamViewer/RustDesk/VNC)", model.AspectRemote,
		remoteCtrlKeys,
		define.CheckOpt{
			Syntax: model.SyntaxReg,
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
	define.WindowsCheck("sunlogin", "Sunlogin Client Logs and Access Code", model.AspectRemote,
		[]model.Probe{PSProbe("log", sunloginScript)},
		define.CheckOpt{
			Filters: []model.LineFilter{
				model.NewFilter("sunlogin-keep", sunloginKeep, model.FilterKeep),
			},
			Rules: []model.Rule{
				model.NewRule("sunlogin-remote-cmd", `(?i)path:\s*/check\?cmd=`, model.High,
					"remote command executed through the Sunlogin HTTP interface"),
				model.NewRule("sunlogin-verify-haras", `(?i)/cgi-bin/rpc\?action=verify-haras`, model.Medium,
					"Sunlogin verify-string request (the exploit's first step)"),
				model.NewRule("sunlogin-connection", `(?i)new acceptor\s+\S+-->`, model.Low,
					"connection accepted by the Sunlogin client"),
				model.NewRule("sunlogin-access-code", `(?i)^\s*encry_pwd\s*=\s*\S`, model.Low,
					"Sunlogin access code stored in the client config"),
				define.KeywordRule,
			},
			Timeout: winlogTimeout,
		}),
}
