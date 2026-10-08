// timeline timeline: ActivitiesCache.db and Sticky Notes.
//
// Both are SQLite, and the Windows target has no built-in sqlite3, so this is a degraded
// string-extraction fallback: read bytes as UTF-8 and extract printable strings. The database file is
// locked while in use, so it is opened with FileShare.ReadWrite; ActivitiesCache output is narrowed
// by a keep filter to path- and URL-shaped lines, and SQL schema words are removed by a drop filter.

package windows

import (
	"fmt"
	"strconv"
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

// stringsScript string-extraction script: read each file matching the globs,
// decode it with encoding ("UTF8" or "Unicode"), extract printable runs of minRun
// or more, deduplicate, one section per file. The section title is printed only
// when there is body text (or a read failure): a readable file with zero hits
// leaves no ghost section. The foreach header stays on one line and pipelines do
// not trail at line end: PS 5.1 treats a newline inside a statement as a
// separator, and a trailing pipe is a straight parse error (hit on a real Server
// 2025 box).
func stringsProbe(encoding string, minRun int, globs ...string) model.Probe {
	extract := `[regex]::Matches($t, '[\x20-\x7E\u4E00-\u9FFF]{` + strconv.Itoa(minRun) + `,}') | ForEach-Object { $_.Value } | Select-Object -Unique`
	return PSFilesProbe("strings", PSListPaths(globs, "", false), func(path string) string {
		// The file is opened with the ReadWrite share mode, so a database a running
		// process holds open can still be read; a read that fails says so on the
		// section's own line rather than leaving a silent gap.
		return fmt.Sprintf(`try {
  $fs = [IO.File]::Open(%s, 'Open', 'Read', 'ReadWrite')
  $ms = New-Object IO.MemoryStream
  $fs.CopyTo($ms); $fs.Close()
  $t = [Text.Encoding]%s.GetString($ms.ToArray())
  %s
} catch {
  'read failed: ' + $_.Exception.Message
}`, PSQuote(path), encoding, extract)
	})
}

// What is forensically interesting in timeline databases is paths and URLs; schema words (table/column names) are suppressed.
const activityShape = `(?i)([a-z]:\\|https?://|\\\\|\.(?:exe|dll|lnk|docx?|xlsx?|pptx?|pdf|txt|ps1|zip|7z|rar)\b)`
const sqlSchema = `^(?:CREATE|INDEX|TABLE|UNIQUE|PRAGMA|sqlite_|IN\s*\(|NOT\s+NULL|DEFAULT` +
	`|PRIMARY|FOREIGN|REFERENCES|CONSTRAINT|CHECK\s*\()`

// TimelineChecks is the timeline aspect.
var TimelineChecks = []*model.Check{
	define.WindowsCheck("activity-cache", "Activity Timeline (ActivitiesCache, String Extraction)", model.AspectTimeline,
		[]model.Step{{stringsProbe("UTF8", 8, activityGlob)}},
		model.Options{
			Timeout: stringsTimeout,
			Filters: []model.LineFilter{
				model.NewFilter("activity-shape", activityShape, model.FilterKeep),
			},
			Rules: []model.Matcher{define.KeywordRule},
		}),
	define.WindowsCheck("sticky-notes", "Sticky Notes Content (String Extraction)", model.AspectTimeline,
		[]model.Step{{stringsProbe("UTF8", 6, stickyGlob)}},
		model.Options{
			Timeout: stringsTimeout,
			Filters: []model.LineFilter{
				model.NewFilter("sql-schema", sqlSchema, model.FilterDrop),
			},
			Rules: []model.Matcher{define.KeywordRule, define.PrivateKeyRule},
		}),
}
