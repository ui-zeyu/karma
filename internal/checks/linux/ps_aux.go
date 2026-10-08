// The sorted aux views' sh tier: the two `ps aux --sort` spellings top's
// resource snapshot asks for, and the parser that reads them back into the aux
// schema the native tiers state. Same shape as ps_ef.go: the command is the
// schema, the parse is karma's code.

package linux

import (
	"regexp"
	"strings"

	"karma/internal/checks/linux/native"
	"karma/internal/model"
)

// psAuxScript is one sorted aux view's sh tier. LC_ALL=C pins the field
// spellings, and ww keeps the command line whole on a pty channel (procps cuts
// COMMAND at the terminal's width otherwise). The parser knows exactly this
// wording and declines anything else.
func psAuxScript(command ...string) model.Script {
	return model.Script{Run: "LC_ALL=C " + strings.Join(command, " "), Parse: psAuxSchema.parse}
}

// psAuxSchema is the aux table: the auxww schema, and the shapes its cells carry
// before the command line — the two percentages aux prints with one decimal, the
// two sizes, the terminal as procps names it, the state string, the start clock
// and the accumulated time. The header alone does not tell this table from
// another system's ps, so the dialect is what the parser reads to decline a
// foreign one.
var psAuxSchema = psSchema{
	name:    "ps aux",
	columns: native.PsAuxColumns,
	dialects: []*regexp.Regexp{
		regexp.MustCompile(`^\d+$`),                                        // PID
		regexp.MustCompile(`^\d+(?:\.\d+)?$`),                              // %CPU
		regexp.MustCompile(`^\d+(?:\.\d+)?$`),                              // %MEM
		regexp.MustCompile(`^\d+$`),                                        // VSZ
		regexp.MustCompile(`^\d+$`),                                        // RSS
		regexp.MustCompile(`^(\?|pts/\d+|ttyS?\d*|console|ptmx|\d+:\d+)$`), // TTY
		regexp.MustCompile(`^[A-Za-z<>NslL+]+$`),                           // STAT
		regexp.MustCompile(`^(\d{1,2}:\d{2}|\d{4}|[A-Z][a-z]{2}\d{1,2})$`), // START
		regexp.MustCompile(`^\d+:\d{2}(:\d{2})?$`),                         // TIME
	},
}
