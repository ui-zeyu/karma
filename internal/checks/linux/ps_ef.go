// The ps command's sh tier: the pinned spelling the sh source runs, and the
// parser that reads it back into the native tier's schema. This is the first
// Script tier — the command is the schema, and the parse is karma's code.

package linux

import (
	"regexp"

	"karma/internal/checks/linux/native"
	"karma/internal/model"
)

// psEfScript is the ps and pstree checks' sh tier: `ps -ef`, the System V table
// the native read states, as the target's own ps prints it. LC_ALL=C pins the
// month names and the field spellings the parser knows, and ww keeps the command
// line whole on a pty channel — procps cuts CMD at the terminal's width (80 by
// default, and `stty cols 0` does not stop it). The parser knows exactly this
// wording and declines anything else (a busybox ps prints a different header,
// which is the tier's failure rather than a guessed-at table).
var psEfScript = model.Script{Run: "LC_ALL=C ps -efww", Parse: psEfSchema.parse}

// psEfSchema is `ps -ef`'s table: the System V schema, and the shapes its cells
// carry before the command line — the two links and the cpu tick, STIME as
// procps spells it (a clock for a start today, the month and day for an earlier
// one, a year for an older one), a terminal as procps names it, and the
// accumulated time. A header alone does not tell this table from another
// system's ps — BSD's `ps -ef` prints the same eight names with "29Sep26", "??"
// and "100:14.77" under them — so the dialect is what the parser reads to
// decline a foreign one.
var psEfSchema = psSchema{
	name:    "ps -ef",
	columns: native.PsEfColumns,
	dialects: []*regexp.Regexp{
		regexp.MustCompile(`^\d+$`),                                        // PID
		regexp.MustCompile(`^\d+$`),                                        // PPID
		regexp.MustCompile(`^\d+$`),                                        // C
		regexp.MustCompile(`^(\d{1,2}:\d{2}|\d{4}|[A-Z][a-z]{2}\d{1,2})$`), // STIME
		regexp.MustCompile(`^(\?|pts/\d+|ttyS?\d*|console|ptmx|\d+:\d+)$`), // TTY
		regexp.MustCompile(`^\d+:\d{2}(:\d{2})?$`),                         // TIME
	},
}
