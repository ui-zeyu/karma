// system system information: software inventory, patches, environment variables, shares, RDP switches.

package windows

import (
	"karma/internal/define"
	"karma/internal/model"
)

// Software inventory over three Uninstall views: 64-bit, 32-bit redirected, current user.
const softwareScript = `foreach ($p in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*') { Get-ItemProperty $p -ErrorAction SilentlyContinue | ForEach-Object { if ($_.DisplayName) { $_.DisplayName + ' | ' + $_.DisplayVersion + ' | ' + $_.InstallDate } } }`

// Common display names of pentest and password tools; remote-control/ops tools are a separate rule.
const softwarePentest = `(?i)\b(?:mimikatz|impacket|psexec|wmiexec|mimipenguin|pwdump|quarkspwdump|hashcat|ophcrack|saminside|getpass|earthworm|regeorg|fscan|frp|ew\.exe|htrans)\b`
const softwareRemote = `(?i)(?:sunlogin|oray|todesk|teamviewer|rustdesk|anydesk|vnc|向日葵)`

const hotfixScript = `Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn | ForEach-Object { if ($_.InstalledOn) { $_.HotFixID + '  ' + $_.InstalledOn.ToString('yyyy-MM-dd') + '  ' + $_.Description } else { $_.HotFixID + '  ' + $_.Description } }`

// Environment variables come in system and user copies; a PATH entry in a user-writable directory is
// a DLL/EXE hijack surface. The last component may end without a semicolon, caught by the `$` arm
// (same lesson as the trailing empty component in env-path-dot).
const envPathSuspicious = `(?i)^\s*Path\s+REG_\w+\s+.*\\(?:Temp(?:\\|;|$)|Users\\Public(?:\\|;|$))`

// Shares are listed from the registry; default administrative shares are filtered out, leaving only custom shares.
const sharesScript = `$defaults = 'ADMIN$','C$','IPC$','PRINT$','NETLOGON','SYSVOL','FAX$'; ` +
	`Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares\*' -ErrorAction SilentlyContinue | ` +
	`ForEach-Object { $n = $_.PSChildName; if ($defaults -notcontains $n) { $n + ' -> ' + $_.Path } }`

const customShare = `^[^\s]+ -> [A-Za-z]:\\`

// The RDP switch, NLA, and port are the three facts about the brute-force entry point.
const rdpEnabledRule = `fDenyTSConnections\s+REG_DWORD\s+0x0\b`
const rdpNLAOffRule = `UserAuthentication\s+REG_DWORD\s+0x0\b`

// SystemChecks is the system information aspect.
var SystemChecks = []*model.Check{
	define.WindowsCheck("software", "Installed Software Inventory (Uninstall)", model.AspectSystem,
		[]model.Probe{PSProbe("reg", softwareScript)},
		define.CheckOpt{
			Syntax: "pipe",
			Rules: []model.Rule{
				model.NewRule("software-pentest", softwarePentest, model.High,
					"password/pentest tool in software inventory"),
				model.NewRule("software-remote", softwareRemote, model.Medium,
					"remote control software in software inventory"),
				define.KeywordRule,
			},
		}),
	define.WindowsCheck("hotfixes", "Patch List (Get-HotFix)", model.AspectSystem,
		[]model.Probe{PSProbe("cim", hotfixScript)},
		define.CheckOpt{Rules: []model.Rule{define.KeywordRule}}),
	RegCheck("env-vars", "Environment Variables (System and User)", model.AspectSystem,
		[]RegKey{
			{Path: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, Label: "hklm"},
			{Path: `HKCU\Environment`, Label: "hkcu"},
		},
		define.CheckOpt{
			Syntax: "reg",
			Rules: []model.Rule{
				model.NewRule("env-path-suspicious", envPathSuspicious, model.Medium,
					"PATH contains temp/public directory (hijack surface)"),
				define.KeywordRule,
			},
		}),
	define.WindowsCheck("shares", "Share List (LanmanServer)", model.AspectSystem,
		[]model.Probe{PSProbe("reg", sharesScript)},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("custom-share", customShare, model.Medium,
					"custom share present"),
				define.KeywordRule,
			},
		}),
	RegCheck("rdp-config", "Remote Desktop Switches and Authentication (RDP)", model.AspectSystem,
		[]RegKey{
			{Path: `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`, Value: "fDenyTSConnections", Label: "termserver"},
			{Path: `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`, Value: "UserAuthentication", Label: "nla"},
			{Path: `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, Value: "PortNumber", Label: "port"},
		},
		define.CheckOpt{
			Syntax: "reg",
			Rules: []model.Rule{
				model.NewRule("rdp-enabled", rdpEnabledRule, model.Medium,
					"Remote Desktop enabled (brute-force surface)"),
				model.NewRule("rdp-nla-off", rdpNLAOffRule, model.Medium,
					"RDP does not enforce NLA"),
				define.KeywordRule,
			},
		}),
}
