// process process surface: process list with command lines.

package windows

import (
	"karma/internal/define"
	"karma/internal/model"
)

// One line per process: PID, process name, command line; the command line is the main evidence for process forensics.
const processesScript = `Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Sort-Object ProcessId | ForEach-Object { $_.ProcessId.ToString() + '  ' + $_.Name + '  ' + $_.CommandLine }`

const procTempExe = `(?i)\\Temp\\[^\s]*\.(?:exe|bat|ps1|vbs|js|dll)`
const procPayload = `(?i)(?:\s-enc(?:odedcommand)?\s|\bdownloadstring\b|\binvoke-expression\b|\s-w\s+(?:hidden|minimized)|frombase64string)`

// ProcessChecks is the process aspect.
var ProcessChecks = []*model.Check{
	define.WindowsCheck("processes", "Process List (with Command Line)", model.AspectProcess,
		[]model.Step{{PSProbe("cim", processesScript)}},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("proc-temp-exe", procTempExe, model.High,
					"executable running from temp directory"),
				model.NewRule("proc-payload", procPayload, model.High,
					"process command line with payload execution traits"),
				define.KeywordRule,
			},
		}),
}
