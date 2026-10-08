// winlog event-log surface: key Security log events and PowerShell script block logging.
//
// Get-WinEvent filters by Id via the event index, capped by MaxEvents; when auditing is off for the
// Security log the probe fails silently. Message extraction uses bilingual field names so both
// Chinese and English systems yield the key lines: account name, source address, service name.

package windows

import (
	"fmt"
	"time"

	"karma/internal/define"
	"karma/internal/model"
	"karma/internal/powershell"
	"karma/internal/script"
)

// Relaxed event timeout: filtering the Security log by Id may still scan hundreds of thousands of records.
const winlogTimeout = 60 * time.Second

const winlogHelper = `function Fmt-Ev($e) { $t = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); ` +
	`$f = ($e.Message -split '\r?\n' | Where-Object { $_ -match '帐户名|源网络地址|工作站|服务名|服务文件|Account Name\s*[::]|Source Network Address|Workstation Name\s*[::]|Service Name|Service File' }) -join ' | '; $t + '  ' + $f }`

// Event ids live in different logs: logon failure, account creation, and audit
// clearing are Security log events; 7045 (service installed) is written to the
// System log by the Service Control Manager and never appears in Security.
const (
	logonFailedEvent   = 4625
	userCreatedEvent   = 4720
	serviceInstallEvt  = 7045
	auditClearedEvent  = 1102
	scriptBlockEvent   = 4104
	secLogName         = "Security"
	systemLogName      = "System"
	scriptBlockLogName = "Microsoft-Windows-PowerShell/Operational"
)

// winlogQuery is one Get-WinEvent probe fragment: filter by log and id, project
// each event. The section it answers with is titled by the probe that runs it.
func winlogQuery(log string, id, maxEvents int, project string) string {
	return fmt.Sprintf("Get-WinEvent -FilterHashtable @{LogName='%s'; Id=%d} -MaxEvents %d -ErrorAction SilentlyContinue | ForEach-Object { %s }",
		log, id, maxEvents, project)
}

// winlogProbe is one event query as its own probe, its section titled with the
// event it reads: the helper the projection uses travels with every probe, since
// each one is a PowerShell call of its own.
func winlogProbe(log string, id, maxEvents int, title, project string) model.Probe {
	return model.Probe{
		Label: "event",
		Title: title,
		Inv:   powershell.PowerShell(script.Lines(winlogHelper, winlogQuery(log, id, maxEvents, project))),
	}
}

const eventLine = "Fmt-Ev $_"
const messageLine = `$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + '  ' + $_.Message`

var secLogProbes = []model.Probe{
	winlogProbe(secLogName, logonFailedEvent, 15, "4625 Logon Failed", eventLine),
	winlogProbe(secLogName, userCreatedEvent, 15, "4720 User Created", eventLine),
	winlogProbe(systemLogName, serviceInstallEvt, 15, "7045 Service Installed", eventLine),
	winlogProbe(secLogName, auditClearedEvent, 5, "1102 Audit Log Cleared", messageLine),
}

const logClearedRule = `^1102\s`

var scriptBlockProbe = winlogProbe(scriptBlockLogName, scriptBlockEvent, 25, "4104 Script Block",
	"$m = $_.Message -replace '\\r?\\n', ' '; $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + '  ' + $m.Substring(0, [Math]::Min(240, $m.Length))")

// scriptBlockSelf: karma's own probe scripts also get logged by 4104 on the target; filter lines by
// features unique to karma (our function names, the artifact names we collect, property GUIDs).
// Common attacker words (Run key, OutputEncoding, Get-ItemProperty, etc.) are not filtered, to
// avoid dropping real payloads and creating a blind spot.
var scriptBlockSelf = model.NewFilter("scriptblock-self",
	`83da6326-97a6-4088-9453-a1923f573b29|Fmt-Ev|Fmt-Time|8wekyb3d8bbwe|plum\.sqlite`+
		`|ConnectedDevicesPlatform|ConsoleHost_history\.txt|\$fs\.CopyTo\(\$ms\)`+
		`|reg query \$p /s|Get-Content -LiteralPath \$f\.FullName|FilterHashtable`+
		`|WordWheelQuery|TypedPaths|RunMRU|BagMRU|ComDlg32|RecentDocs|cRecentFiles|ArcHistory|SimonTatham`,
	model.FilterDrop)

// WinLogChecks is the log aspect.
var WinLogChecks = []*model.Check{
	define.WindowsCheck("sec-log", "Key Security Log Events (Logon Failure/Account Creation/Service Install/Log Cleared)", model.AspectLog,
		[]model.Step{secLogProbes},
		model.Options{
			Timeout: winlogTimeout,
			Rules: []model.Matcher{
				model.NewRule("log-cleared", logClearedRule, model.Medium,
					"audit log cleared (anti-forensics)"),
				define.KeywordRule,
			},
		}),
	define.WindowsCheck("scriptblock-log", "PowerShell Script Block Log (4104)", model.AspectLog,
		[]model.Step{{scriptBlockProbe}},
		model.Options{
			Timeout: winlogTimeout,
			Filters: []model.LineFilter{scriptBlockSelf},
			Rules: []model.Matcher{
				model.NewRule("scriptblock-payload", historySuspicious, model.High,
					"script block log with payload execution traits"),
				define.KeywordRule,
			},
		}),
}
