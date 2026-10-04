// timeline timeline: ActivitiesCache.db and Sticky Notes.
//
// Both are SQLite, and the Windows target has no built-in sqlite3, so this is a degraded
// string-extraction fallback: read bytes as UTF-8 and extract printable strings. The database file is
// locked while in use, so it is opened with FileShare.ReadWrite; ActivitiesCache output is narrowed
// by a keep filter to path- and URL-shaped lines, and SQL schema words are removed by a drop filter.

package windows

import (
	"fmt"
	"time"

	"karma/internal/define"
	"karma/internal/model"
)

const activityGlob = `C:\Users\*\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db`
const stickyGlob = `C:\Users\*\AppData\Local\Packages` +
	`\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite*`

// stringsTimeout relaxes the whole-database string-extraction probe: a SQLite file can be tens of MB
// and a full regex scan may hit the default 30s and leave only half (same as jumplists).
const stringsTimeout = 60 * time.Second

// stringsScript string-extraction script: read bytes as UTF-8, extract printable strings, deduplicate, output.
// The section title is printed only when there is body text (or a read failure): a readable file with
// zero hits leaves no ghost section. The foreach header stays on one line and pipelines do not trail
// at line end: PS 5.1 treats a newline inside a statement as a separator, and a trailing pipe is a
// straight parse error (hit on a real Server 2025 box).
func stringsScript(glob string, minRun int) string {
	return fmt.Sprintf(`foreach ($f in Get-ChildItem '%s' -File -ErrorAction SilentlyContinue) {
  try {
    $fs = [IO.File]::Open($f.FullName, 'Open', 'Read', 'ReadWrite')
    $ms = New-Object IO.MemoryStream
    $fs.CopyTo($ms); $fs.Close()
    $t = [Text.Encoding]::UTF8.GetString($ms.ToArray())
    $s = [regex]::Matches($t, '[\x20-\x7E\u4E00-\u9FFF]{%d,}') | ForEach-Object { $_.Value } | Select-Object -Unique
    if ($s) { "== " + $f.FullName; $s }
  } catch {
    "== " + $f.FullName
    "read failed: " + $_.Exception.Message
  }
}`, glob, minRun)
}

// What is forensically interesting in timeline databases is paths and URLs; schema words (table/column names) are suppressed.
const activityShape = `(?i)([a-z]:\\|https?://|\\\\|\.(?:exe|dll|lnk|docx?|xlsx?|pptx?|pdf|txt|ps1|zip|7z|rar)\b)`
const sqlSchema = `^(?:CREATE|INDEX|TABLE|UNIQUE|PRAGMA|sqlite_|IN\s*\(|NOT\s+NULL|DEFAULT` +
	`|PRIMARY|FOREIGN|REFERENCES|CONSTRAINT|CHECK\s*\()`

// TimelineChecks is the timeline aspect.
var TimelineChecks = []*model.Check{
	define.WindowsCheck("activity-cache", "Activity Timeline (ActivitiesCache, String Extraction)", model.AspectTimeline,
		[]model.Probe{PSProbe("strings", stringsScript(activityGlob, 8))},
		define.CheckOpt{
			Timeout: stringsTimeout,
			Filters: []model.LineFilter{
				model.NewFilter("activity-shape", activityShape, model.FilterKeep),
			},
			Rules: []model.Rule{define.KeywordRule},
		}),
	define.WindowsCheck("sticky-notes", "Sticky Notes Content (String Extraction)", model.AspectTimeline,
		[]model.Probe{PSProbe("strings", stringsScript(stickyGlob, 6))},
		define.CheckOpt{
			Timeout: stringsTimeout,
			Filters: []model.LineFilter{
				model.NewFilter("sql-schema", sqlSchema, model.FilterDrop),
			},
			Rules: []model.Rule{define.KeywordRule, define.PrivateKeyRule},
		}),
}
