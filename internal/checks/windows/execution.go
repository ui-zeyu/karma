// execution program execution artifacts: UserAssist, RunMRU, PowerShell history, clipboard.

package windows

import (
	"encoding/binary"
	"slices"
	"strconv"
	"strings"

	"karma/internal/define"
	"karma/internal/model"
	"karma/internal/regout"
	"karma/internal/script"
)

const userassistKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`
const advancedKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`

// reg.exe prints a zero DWORD as 0x0; either switch being 0 means tracking is off
const trackDisabled = `Start_Track(?:Enabled|Progs)\s+REG_DWORD\s+0x0\b`

const suspiciousPath = `(?:\\(?:Temp|Downloads)\\|\\AppData\\Local\\Temp\\).*\.(?:exe|bat|ps1|vbs|js)\b`

const runmruKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`

// UNC paths and suspicious arguments are lateral-movement/payload traits in the Run box
const runUNC = `\\\\[A-Za-z0-9_.-]+\\`

const runSuspicious = `(?i)(?:\bmshta\b|-enc(?:odedcommand)?\b|\b-iex\b` +
	`|invoke-expression|downloadstring|-w\s+hidden\b)`

const psHistoryGlob = `C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell` +
	`\PSReadline\ConsoleHost_history.txt`

// PS readline history persists across sessions; Clear-History only clears memory, leaving evidence of a botched history wipe in the file
const historySuspicious = `(?i)(?:\bmshta\b|certutil\s+[^|\n]*urlcache|-enc(?:odedcommand)?\b|\b-iex\b` +
	`|invoke-expression|downloadstring)`

var userassistKeys = []RegKey{
	{Path: userassistKey, Recurse: true, Label: "reg-direct"},
}

var trackKeys = []RegKey{
	{Path: advancedKey, Value: "Start_TrackEnabled", Label: "enabled"},
	{Path: advancedKey, Value: "Start_TrackProgs", Label: "progs"},
}

var runmruKeys = []RegKey{
	{Path: runmruKey, Label: "reg-direct"},
}

// The script is fed wholesale into powershell -Command: a newline inside a statement is a statement
// separator for PS 5.1, so a foreach header must stay on one line and pipeline continuation must
// be avoided. An empty history file gets no section header, avoiding a ghost section.
var psHistoryScript = script.Lines(
	"foreach ($f in Get-ChildItem '"+psHistoryGlob+"' -File -ErrorAction SilentlyContinue) {",
	"  "+psSection(`"== " + $f.FullName`, "Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue"),
	"}")

const clipboardScript = "Get-Clipboard -Raw -ErrorAction SilentlyContinue"

// Non-behavioral entries in userassist subkeys: Version is a per-subkey format version number, and
// UEME_CTLSESSION / UEME_CTLCUACount are session and UAC-elevation counters repeated in every GUID
// subkey, pure noise. Compared against the restored names.
var userassistNoise = map[string]bool{
	"Version":               true,
	"UEME_CTLSESSION":       true,
	"UEME_CTLCUACount:ctor": true,
}

// userassistNormalize: restore ROT-13 value names, translate known folder prefixes, and read the
// run count from the binary.
//
// Non-binary values (DWORD switches like Start_TrackEnabled) are kept as-is in
// `name type data` lines, left to the rules to decide whether tracking is off.
func userassistNormalize(_ string, body string) *model.Shaped {
	var lines []string
	for _, value := range regout.ParseRegValues(body) {
		if value.Type != "REG_BINARY" {
			if value.Data != "" && !userassistNoise[value.Name] {
				lines = append(lines, value.Name+" "+value.Type+" "+value.Data)
			}
			continue
		}
		name := TranslateKnownFolder(ROT13(value.Name))
		if userassistNoise[name] {
			continue
		}
		data := regout.HexBytes(value.Data)
		var line string
		if len(data) >= 8 {
			count := binary.LittleEndian.Uint32(data[4:8])
			line = name + " · ran " + strconv.FormatUint(uint64(count), 10) + " times"
		} else {
			line = name
		}
		lines = append(lines, line)
	}
	return &model.Shaped{Text: strings.Join(lines, "\n")}
}

// runmruNormalize restores input order from the MRUList letter string, stripping the trailing \1 count suffix.
func runmruNormalize(_ string, body string) *model.Shaped {
	values := regout.ParseRegValues(body)
	order := ""
	commands := map[string]string{}
	var fallback []string
	for _, value := range values {
		if value.Name == "MRUList" {
			order = value.Data
		} else {
			commands[value.Name] = value.Data
			fallback = append(fallback, value.Name)
		}
	}
	slices.Sort(fallback)
	var names []string
	for _, ch := range order {
		if _, ok := commands[string(ch)]; ok {
			names = append(names, string(ch))
		}
	}
	if len(names) == 0 {
		names = fallback
	}
	var lines []string
	for _, name := range names {
		lines = append(lines, strings.TrimSuffix(commands[name], `\1`))
	}
	return &model.Shaped{Text: strings.Join(lines, "\n")}
}

// ExecutionChecks is the execution-artifacts aspect.
var ExecutionChecks = []*model.Check{
	RegCheck("userassist", "Program Execution History (UserAssist)", model.AspectExecution,
		userassistKeys,
		define.CheckOpt{
			Normalize: userassistNormalize,
			Rules: []model.Rule{
				model.NewRule("userassist-suspicious-path", suspiciousPath, model.Medium,
					"executable run from an unusual location"),
			},
		}),
	// Tracking switches are a separate check: the direct-run probe chains /v probes, and the old/new
	// difference between the two switch names (Win7+ is Start_TrackEnabled, XP only had Start_TrackProgs)
	// is handled naturally by fallback semantics--a missing probe gives an empty/non-zero body, so it moves to the next
	RegCheck("userassist-track", "Program Execution Tracking Switches (Anti-Forensics)", model.AspectExecution,
		trackKeys,
		define.CheckOpt{
			Syntax: "reg",
			Rules: []model.Rule{
				model.NewRule("userassist-track-disabled", trackDisabled, model.High,
					"UserAssist program execution tracking disabled"),
			},
		}),
	RegCheck("runmru", "Run Command History (RunMRU)", model.AspectExecution,
		runmruKeys,
		define.CheckOpt{
			Normalize: runmruNormalize,
			Rules: []model.Rule{
				model.NewRule("runmru-unc-path", runUNC, model.Medium, "network share path accessed from Run box"),
				model.NewRule("runmru-suspicious", runSuspicious, model.High, "Run command with payload execution traits"),
				define.KeywordRule,
			},
		}),
	define.WindowsCheck("psreadline", "PowerShell Command History", model.AspectExecution,
		[]model.Probe{PSProbe("type", psHistoryScript)},
		define.CheckOpt{
			Syntax: "powershell",
			Rules: []model.Rule{
				model.NewRule("psreadline-suspicious", historySuspicious, model.High,
					"history command with payload execution traits"),
				model.NewRule("psreadline-clear-history", `\bClear-History\b`, model.High,
					"history cleared (still recorded in file)"),
				define.KeywordRule,
			},
		}),
	define.WindowsCheck("clipboard", "Current Clipboard Content", model.AspectExecution,
		[]model.Probe{PSProbe("clipboard", clipboardScript)},
		define.CheckOpt{
			Rules: []model.Rule{define.KeywordRule, define.PrivateKeyRule},
		}),
}
