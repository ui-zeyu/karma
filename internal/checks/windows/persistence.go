// persistence persistence surface: autoruns, services, scheduled tasks, WMI event subscriptions.

package windows

import (
	"karma/internal/define"
	"karma/internal/model"
)

// run-keys: five registry autoruns plus two startup folders, produced by one script.
var runKeyFragments = []string{
	RegQuery(`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, false),
	RegQuery(`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, false),
	RegQuery(`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, false),
	RegQuery(`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, false),
	RegQuery(`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, false),
	`$o = Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup","$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }; if ($o) { '== Startup Folder'; $o }`,
}

var runKeysScript = RegScript(runKeyFragments...)

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

const wmiSubscriptionScript = `foreach ($c in '__EventFilter','CommandLineEventConsumer','ActiveScriptEventConsumer','__FilterToConsumerBinding') { $o = Get-CimInstance -Namespace root\subscription -Class $c -ErrorAction SilentlyContinue | Format-List Name,Query,CommandLineTemplate,ScriptText; if ($o) { '== ' + $c; $o } }`

// Non-empty CommandLineTemplate or ScriptText means subscription persistence; on a default machine
// these three are all empty.
const wmiConsumerRule = `(?i)^(?:CommandLineTemplate|ScriptText)\s*:\s*\S`

// PersistenceChecks is the persistence aspect.
var PersistenceChecks = []*model.Check{
	define.WindowsCheck("run-keys", "Autorun Entries (Run Keys and Startup Folders)", model.AspectPersistence,
		[]model.Probe{
			PSProbe("reg", runKeysScript),
			RegDirectProbe("hklm-run", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, false, ""),
			RegDirectProbe("hklm-runonce", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, false, ""),
			RegDirectProbe("hklm-wow", `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, false, ""),
			RegDirectProbe("hkcu-run", `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, false, ""),
			RegDirectProbe("hkcu-runonce", `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, false, ""),
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
		}),
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
}
