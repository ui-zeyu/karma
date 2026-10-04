// persistence persistence surface: autoruns, services, scheduled tasks, WMI event subscriptions.

package windows

import (
	"karma/internal/define"
	"karma/internal/model"
)

// run-keys: five registry autoruns plus two startup folders, produced by one script.
var startupFolderFragment = psSection("'Startup Folder'",
	`Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup","$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }`)

const autorunTempRule = `(?i)\\(?:Temp|Users\\Public)\\[^\s]*\.(?:exe|bat|ps1|vbs|js|hta)\b`
const autorunPayloadRule = `(?i)(?:\bmshta\b|-enc(?:odedcommand)?\b|\b-iex\b|invoke-expression|downloadstring|-w\s+hidden\b|rundll32\b[^\n]*(?:javascript|vbscript))`

// One line per service: name, state, start mode, binPath. A path in a temp directory is another kind
// of obvious malice beyond fileless execution; an unquoted path with spaces under Program Files is a
// classic hijack surface.
const servicesScript = `Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object { $_.Name + '  ' + $_.State + '  ' + $_.StartMode + '  ' + $_.PathName }`

const serviceTempRule = `(?i)\\(?:Temp|Users\\Public)\\[^\s]*\.(?:exe|dll|bat|ps1|vbs|js)`
const serviceUnquotedRule = `(?i)\s[A-Za-z]:\\(?:Program Files|Program Files \(x86\))\\[^"]*\s[^"]*\.(?:exe|dll)\s*$`

// Scheduled tasks go through Get-ScheduledTask: Execute and Arguments in Actions are what matters
// (the schtasks CSV only has task name and state).
const tasksScript = `Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { $a = ($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' ; '; $_.TaskPath + $_.TaskName + '  ' + $_.State + '  ' + $a }`

var wmiSubscriptionScript = `foreach ($c in '__EventFilter','CommandLineEventConsumer','ActiveScriptEventConsumer','__FilterToConsumerBinding') { ` +
	psSection("$c", `Get-CimInstance -Namespace root\subscription -Class $c -ErrorAction SilentlyContinue | Format-List Name,Query,CommandLineTemplate,ScriptText`) +
	` }`

// Non-empty CommandLineTemplate or ScriptText means subscription persistence; on a default machine
// these three are all empty.
const wmiConsumerRule = `(?i)^(?:CommandLineTemplate|ScriptText)\s*:\s*\S`

// ifeoKeys: Image File Execution Options carries a per-executable Debugger value
// that takes over the process at launch (the classic sticky-keys trick: point
// sethc.exe at cmd.exe); SilentProcessExit does the same for a process that is
// observed to exit. Both live under keys a stock machine leaves empty of
// Debugger/MonitorProcess values.
var ifeoKeys = []RegKey{
	{Path: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, Recurse: true, Label: "ifeo"},
	{Path: `HKLM\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, Recurse: true, Label: "ifeo-wow64"},
	{Path: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit`, Recurse: true, Label: "silent-process-exit"},
}

const (
	ifeoDebuggerRule = `(?i)^\s+Debugger\s+REG_\w+\s+\S`
	ifeoMonitorRule  = `(?i)^\s+MonitorProcess\s+REG_\w+\s+\S`
)

// winlogonKeys: the logon shell, userinit, notification package, and AppSetup
// command all run inside every interactive logon, and AppInit_DLLs is injected
// into every process that loads user32.
var winlogonKeys = []RegKey{
	{Path: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, Label: "winlogon"},
	{Path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Windows`, Label: "windows"},
	{Path: `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Windows`, Label: "windows-wow64"},
	{Path: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Windows`, Label: "windows-hkcu"},
}

// AppInit_DLLs only takes effect when LoadAppInit_DLLs is 1 (Win8 and later), so
// the switch is worth its own line.
var (
	winlogonShellRule = model.NewRule("winlogon-shell", `(?i)^\s+Shell\s+REG_\w+\s+\S`, model.High,
		"logon shell replaced (runs on every interactive logon)").
		WithExclude(`(?i)^\s+Shell\s+REG_\w+\s+explorer\.exe\s*$`)
	winlogonUserinitRule = model.NewRule("winlogon-userinit", `(?i)^\s+Userinit\s+REG_\w+\s+\S`, model.High,
		"logon userinit replaced (runs on every interactive logon)").
		// only the stock value is quiet, so an appended program is flagged too
		WithExclude(`(?i)^\s+Userinit\s+REG_\w+\s+C:\\Windows\\system32\\userinit\.exe,\s*$`)
	winlogonNotifyRule = model.NewRule("winlogon-notify", `(?i)^\s+Notify\s+REG_\w+\s+\S`, model.Medium,
		"Winlogon notification package registered (runs at logon)")
	winlogonAppSetupRule = model.NewRule("winlogon-appsetup", `(?i)^\s+AppSetup\s+REG_\w+\s+\S`, model.Medium,
		"AppSetup command registered (runs at logon)")
	appinitDllRule = model.NewRule("appinit-dlls", `(?i)^\s+AppInit_DLLs\s+REG_\w+\s+\S`, model.High,
		"AppInit_DLLs set (injected into every process that loads user32)")
	appinitLoadRule = model.NewRule("appinit-load", `(?i)^\s+LoadAppInit_DLLs\s+REG_DWORD\s+0x1\b`, model.Medium,
		"AppInit_DLLs loading enabled")
)

// The layers key holds one value per executable (path = flags); the custom shim
// databases are the other half of shim persistence, gathered by the AppPatch
// fragment that is not a plain reg query.
const appcompatLayersKey = `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers`

var appPatchFragment = psSection("'AppPatch Custom'",
	`Get-ChildItem 'C:\Windows\AppPatch\Custom','C:\Windows\AppPatch\Custom64' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName + '  ' + $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') }`)

var (
	appcompatLayerRule = model.NewRule("appcompat-layer", `(?i)^\s+[A-Za-z]:\\\S*\s+REG_\w+\s+~`, model.Low,
		"per-executable compatibility layer set (confirm it is expected)")
	appcompatTempRule = model.NewRule("appcompat-userpath",
		`(?i)^\s+[A-Za-z]:.*(?:\\Temp\\|\\Users\\Public\\|\\AppData\\).*\.exe\s+REG_\w+\s+~`, model.High,
		"compatibility layer applied to an executable in a user-writable directory")
	appcompatSdbRule = model.NewRule("appcompat-sdb", `(?i)^C:\\Windows\\AppPatch\\Custom(?:64)?\\`,
		model.Medium, "custom compatibility shim database present")
)

// serviceDllScript lists the DLL each svchost service loads: a ServiceDll outside
// the system directories (or in a user-writable one) is the svchost DLL-hijack
// shape.
const serviceDllScript = `Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue | ForEach-Object { $d = (Get-ItemProperty ($_.PSPath + '\Parameters') -ErrorAction SilentlyContinue).ServiceDll; if ($d) { $_.PSChildName + '  ' + $d } }`

var (
	serviceDllTempRule = model.NewRule("svcdll-temp",
		`(?i)\s[A-Za-z]:\\(?:Windows\\Temp|Users\\Public|Users\\[^\\]+\\AppData)\\.*\.dll\s*$`, model.High,
		"svchost service loads a DLL from a user-writable directory (DLL hijack)")
	serviceDllOutsideRule = model.NewRule("svcdll-outside-system", `(?i)\s[A-Za-z]:.*\.dll\s*$`, model.Medium,
		"svchost service DLL outside the system directories (confirm it is expected)").
		// reg.exe prints the unexpanded REG_EXPAND_SZ, PowerShell the expanded one
		WithExclude(`(?i)\s(?:C:\\Windows|%SystemRoot%)\\(?:System32|SysWOW64)\\`)
)

// PersistenceChecks is the persistence aspect.
var PersistenceChecks = []*model.Check{
	RegCheck("run-keys", "Autorun Entries (Run Keys and Startup Folders)", model.AspectPersistence,
		[]RegKey{
			{Path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, Label: "hklm-run"},
			{Path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, Label: "hklm-runonce"},
			{Path: `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, Label: "hklm-wow"},
			{Path: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, Label: "hkcu-run"},
			{Path: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, Label: "hkcu-runonce"},
		},
		define.CheckOpt{
			Syntax: "reg",
			Rules: []model.Rule{
				model.NewRule("autorun-temp", autorunTempRule, model.High,
					"autorun points to temp/public directory"),
				model.NewRule("autorun-payload", autorunPayloadRule, model.High,
					"autorun with payload execution traits"),
				define.KeywordRule,
			},
		},
		startupFolderFragment),
	define.WindowsCheck("nt-services", "Service List (with binPath)", model.AspectPersistence,
		[]model.Probe{PSProbe("cim", servicesScript)},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("svc-temp", serviceTempRule, model.High,
					"service points to temp/public directory"),
				model.NewRule("svc-unquoted", serviceUnquotedRule, model.Medium,
					"service path has spaces and is unquoted (hijack surface)"),
				define.KeywordRule,
			},
		}),
	define.WindowsCheck("tasks", "Scheduled Task List (with Actions)", model.AspectPersistence,
		[]model.Probe{PSProbe("task", tasksScript)},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("task-userpath", autorunTempRule, model.High,
					"scheduled task points to temp/user-writable directory"),
				// Payload traits are independent of path: a task disguised under the built-in \Microsoft\ path
				// still lights up if its command line has mshta/-enc/iex and the like
				model.NewRule("task-payload", autorunPayloadRule, model.High,
					"scheduled task with payload execution traits"),
				define.KeywordRule,
			},
		}),
	define.WindowsCheck("wmi-subscription", "WMI Event Subscriptions (Persistence)", model.AspectPersistence,
		[]model.Probe{PSProbe("cim", wmiSubscriptionScript)},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("wmi-consumer", wmiConsumerRule, model.High,
					"WMI event subscription with consumer content"),
				define.KeywordRule,
			},
		}),
	RegCheck("ifeo", "Debugger Hijack (Image File Execution Options, SilentProcessExit)", model.AspectPersistence,
		ifeoKeys,
		define.CheckOpt{
			Syntax: "reg",
			Rules: []model.Rule{
				model.NewRule("ifeo-debugger", ifeoDebuggerRule, model.High,
					"Debugger value takes over a program at launch (confirm it is expected)"),
				model.NewRule("ifeo-monitor", ifeoMonitorRule, model.High,
					"SilentProcessExit monitor redirects an exiting process"),
				define.KeywordRule,
			},
		}),
	RegCheck("winlogon", "Logon Hooks and DLL Injection (Winlogon, AppInit_DLLs)", model.AspectPersistence,
		winlogonKeys,
		define.CheckOpt{
			Syntax: "reg",
			Rules: []model.Rule{
				winlogonShellRule,
				winlogonUserinitRule,
				winlogonNotifyRule,
				winlogonAppSetupRule,
				appinitDllRule,
				appinitLoadRule,
				define.KeywordRule,
			},
		}),
	RegCheck("appcompat", "Compatibility Shims (AppCompatFlags Layers, custom sdb)", model.AspectPersistence,
		[]RegKey{{Path: appcompatLayersKey, Label: "layers"}},
		define.CheckOpt{
			Syntax: "reg",
			Rules: []model.Rule{
				appcompatTempRule,
				appcompatLayerRule,
				appcompatSdbRule,
				define.KeywordRule,
			},
		},
		appPatchFragment),
	define.WindowsCheck("svc-dll", "svchost Service DLLs (ServiceDll)", model.AspectPersistence,
		[]model.Probe{PSProbe("cim", serviceDllScript)},
		define.CheckOpt{
			Rules: []model.Rule{
				serviceDllTempRule,
				serviceDllOutsideRule,
				define.KeywordRule,
			},
		}),
}
