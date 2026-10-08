// documents file access artifacts: RecentDocs, ComDlg32, Office/Adobe MRU, LNK,
// archives, JumpLists.
//
// JumpLists is a degraded fallback: it does not parse the OLE structure of .automaticDestinations-ms,
// instead extracting UTF-16 strings from the file to recover "which paths this app touched".

package windows

import (
	"strconv"
	"strings"

	"github.com/samber/lo"

	"karma/internal/define"
	"karma/internal/model"
	"karma/internal/powershell"
	"karma/internal/regout"
	"karma/internal/script"
)

const recentDocsKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`
const comdlg32Key = `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32`

// adobeKeys: each of Adobe's two product generations has a cRecentFiles (DC and Acrobat Reader);
// query one of each when both are present.
var adobeKeys = []RegKey{
	{Path: `HKCU\Software\Adobe\Adobe Acrobat\DC\AVGeneral\cRecentFiles`, Recurse: true, Label: "dc"},
	{Path: `HKCU\Software\Adobe\Acrobat Reader\DC\AVGeneral\cRecentFiles`, Recurse: true, Label: "reader"},
}

// The winzip key pair is the old and new version key names of the same vendor (the old RegRipper
// plugin pointed to Nico Mak, the new one changed to WinZip Computing); the parent key /s covers
// extract and mru\archives at once.
const winzipKey = `HKCU\SOFTWARE\WinZip Computing\WinZip`
const winzipLegacyKey = `HKCU\SOFTWARE\Nico Mak Computing\WinZip`
const winrarKey = `HKCU\Software\WinRAR\ArcHistory`

// officeScript enumerates File/Place MRU per app under version directories (16.0 etc.); User MRU
// (Microsoft account paths) alongside.
var officeProbe = model.Probe{Label: "reg", Inv: model.FileList{
	List: powershell.PowerShell(
		`foreach ($ver in Get-ChildItem 'HKCU:\SOFTWARE\Microsoft\Office' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d' }) { ` +
			`foreach ($app in 'Word','Excel','PowerPoint') { ` +
			`foreach ($mru in 'File MRU','Place MRU','User MRU') { ` +
			`$ver.PSChildName + '\' + $app + '\' + $mru } } }`),
	Read: func(mru string) model.Invocation {
		return powershell.PowerShell(`reg query ` + PSQuote(`HKCU:\SOFTWARE\Microsoft\Office\`+mru) + ` /s 2>$null`)
	},
}}

// lnkScript reads shortcut targets via COM: TargetPath/Arguments/WorkingDirectory cover the
// initial-access lure (mshta+URL) shape; deeper blocks like tracker/MAC need an LNK parser, phase two.
var lnkProbe = PSFilesProbe("com",
	PSListPaths([]string{`C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*.lnk`}, "", false),
	func(path string) string {
		return script.Lines(
			"$sh = New-Object -ComObject WScript.Shell",
			"try {",
			"  $l = $sh.CreateShortcut("+PSQuote(path)+")",
			`  "Target: " + $l.TargetPath`,
			`  if ($l.Arguments) { "Arguments: " + $l.Arguments }`,
			`  if ($l.WorkingDirectory) { "Working Directory: " + $l.WorkingDirectory }`,
			"} catch {}")
	})

// jumplistScript extracts strings from the whole OLE compound document as UTF-16: paths and file
// names are stored as UTF-16LE, with a minimum length of 5 to filter noise. The globs cover the
// files of both destination directories in one probe.
var jumplistProbe = stringsProbe("Unicode", 5,
	`C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*`,
	`C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\*`)

const tempExecutable = `(?i)(?:\\(?:Temp|Downloads)\\|\\AppData\\Local\\Temp\\).*\.(?:ps1|exe|bat|cmd|vbs|js|hta)\b`
const lnkURL = `(?i)Arguments:.*(?:https?://|ftp://)`
const lnkMshta = `(?i)Arguments:.*\bmshta\b`

// officeMruNormalize: in the Item N binary the first 8 bytes are a FILETIME, followed by the UTF-16
// path; output time plus path.
func officeMruNormalize(_ string, body string) *model.Shaped {
	lines := lo.FilterMap(regout.ParseRegValues(body), func(value regout.Value, _ int) (string, bool) {
		if value.Type != "REG_BINARY" {
			return "", false
		}
		data := regout.HexBytes(value.Data)
		found := UTF16Strings(data, 3)
		if len(found) == 0 {
			return "", false
		}
		path := lo.MaxBy(found, func(a, b string) bool { return len(a) < len(b) })
		if when := FiletimeStr(data); when != "" {
			return when + "  " + path, true
		}
		return path, true
	})
	return &model.Shaped{Text: strings.Join(lines, "\n")}
}

// opensaveNormalize classifies the full /s body of ComDlg32 by subkey block: app name list,
// exe→directory, full paths.
//
// In the real pipeline the whole dump lands in one section (one section for PS, the preamble section
// for direct-run); the structure is recovered from flush-left key path lines in the body, and the
// section title is only provenance.
func opensaveNormalize(_ string, body string) *model.Shaped {
	var lines []string
	for _, block := range regout.RegBlocks(body) {
		values := regout.ParseRegValues(block.Body)
		binStrings := make(map[int][]string)
		var indexes []int
		for _, value := range values {
			index, err := strconv.Atoi(value.Name)
			if value.Type != "REG_BINARY" || err != nil {
				continue
			}
			binStrings[index] = UTF16Strings(regout.HexBytes(value.Data), 3)
			indexes = append(indexes, index)
		}
		ordered := lo.Map(blockOrder(MRUListExOrder(values), indexes),
			func(index int, _ int) []string { return binStrings[index] })

		switch {
		case strings.HasSuffix(block.Key, "CIDSizeMRU"):
			lines = append(lines, lo.FilterMap(ordered, func(strs []string, _ int) (string, bool) {
				return lo.FirstOr(strs, ""), len(strs) > 0
			})...)
		case strings.HasSuffix(block.Key, "LastVisitedPidlMRU"):
			for _, strs := range ordered {
				exe, _ := lo.Find(strs, func(s string) bool { return strings.HasSuffix(strings.ToLower(s), ".exe") })
				folders := lo.Filter(strs, func(s string, _ int) bool { return strings.Contains(s, "\\") })
				folder := lo.MaxBy(folders, func(a, b string) bool { return len(a) < len(b) })
				if exe != "" || folder != "" {
					lines = append(lines, strings.TrimSuffix(exe+" → "+folder, " → "))
				}
			}
		case strings.Contains(block.Key, "OpenSavePidlMRU"):
			// full path inside the PIDL, take the longest one
			for _, strs := range ordered {
				paths := lo.Filter(strs, func(s string, _ int) bool {
					return strings.Contains(s, "\\") || strings.Contains(s, "/")
				})
				if len(paths) > 0 {
					lines = append(lines, lo.MaxBy(paths, func(a, b string) bool { return len(a) < len(b) }))
				}
			}
		}
	}
	return &model.Shaped{Text: strings.Join(lines, "\n")}
}

// recentDocsNormalize expands each subkey block (by extension, Folder, root block) in MRUListEx order.
func recentDocsNormalize(_ string, body string) *model.Shaped {
	lines := lo.FlatMap(regout.RegBlocks(body), func(block regout.Block, _ int) []string {
		return MRUTerms(block.Body, 2)
	})
	return &model.Shaped{Text: strings.Join(lines, "\n")}
}

// archiveNormalize for archive tool keys: extract strings from binary values (file names inside
// WinZip archives) and keep named values as-is.
func archiveNormalize(_ string, body string) *model.Shaped {
	var lines []string
	for _, value := range regout.ParseRegValues(body) {
		switch {
		case value.Type == "REG_BINARY":
			lines = append(lines, lo.Uniq(UTF16Strings(regout.HexBytes(value.Data), 3))...)
		case value.Data != "" && isDigits(value.Name):
			lines = append(lines, value.Data)
		case value.Data != "":
			lines = append(lines, value.Name+" = "+value.Data)
		}
	}
	return &model.Shaped{Text: strings.Join(lines, "\n")}
}

func isDigits(text string) bool {
	return text != "" && strings.IndexFunc(text, func(r rune) bool { return r < '0' || r > '9' }) < 0
}

// DocumentsChecks is the file access artifacts aspect.
var DocumentsChecks = []*model.Check{
	RegCheck("recent-docs", "Recent Documents (RecentDocs)", model.AspectDocuments,
		[]RegKey{{Path: recentDocsKey, Recurse: true, Label: "reg-direct"}},
		model.Options{Normalize: recentDocsNormalize, Rules: []model.Matcher{define.KeywordRule}}),
	RegCheck("opensave-mru", "Open/Save Dialog History (ComDlg32)", model.AspectDocuments,
		[]RegKey{{Path: comdlg32Key, Recurse: true, Label: "reg-direct"}},
		model.Options{
			Normalize: opensaveNormalize,
			Rules: []model.Matcher{
				model.NewRule("opensave-temp-exec", tempExecutable, model.High,
					"executable from temp/download directory in dialog"),
				define.KeywordRule,
			},
		}),
	define.WindowsCheck("office-mru", "Office Recent Files (File/Place MRU)", model.AspectDocuments,
		[]model.Step{{officeProbe}},
		model.Options{Normalize: officeMruNormalize, Rules: []model.Matcher{define.KeywordRule}}),
	RegCheck("adobe-recent", "Adobe Recent PDFs (cRecentFiles)", model.AspectDocuments,
		adobeKeys,
		model.Options{Syntax: model.SyntaxReg, Rules: []model.Matcher{define.KeywordRule}}),
	define.WindowsCheck("lnk-recent", "Shortcut Targets (Recent LNK)", model.AspectDocuments,
		[]model.Step{{lnkProbe}},
		model.Options{
			Rules: []model.Matcher{
				model.NewRule("lnk-mshta", lnkMshta, model.Critical,
					"shortcut executes remote content via mshta (lure)"),
				model.NewRule("lnk-url-argument", lnkURL, model.High, "shortcut arguments carry a network address"),
				define.KeywordRule,
			},
		}),
	RegCheck("archive-history", "Archive History (WinZip/WinRAR)", model.AspectDocuments,
		[]RegKey{
			{Path: winzipKey, Recurse: true, Label: "winzip"},
			{Path: winzipLegacyKey, Recurse: true, Label: "winzip-old"},
			{Path: winrarKey, Recurse: true, Label: "winrar"},
		},
		model.Options{Normalize: archiveNormalize, Rules: []model.Matcher{define.KeywordRule}}),
	define.WindowsCheck("jumplists", "Jump Lists (JumpLists, String Extraction)", model.AspectDocuments,
		[]model.Step{{jumplistProbe}},
		model.Options{Timeout: stringsTimeout, Rules: []model.Matcher{define.KeywordRule}}),
}
