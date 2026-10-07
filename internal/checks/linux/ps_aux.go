// The sorted aux views' sh tier: the two `ps aux --sort` spellings top's
// resource snapshot asks for, and the parser that reads them back into the aux
// schema the native tiers state. Same shape as ps_ef.go: the command is the
// schema, the parse is karma's code.

package linux

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"karma/internal/checks/linux/native"
	"karma/internal/model"
)

// psAuxScript is one sorted aux view's sh tier. LC_ALL=C pins the field
// spellings, and ww keeps the command line whole on a pty channel (procps cuts
// COMMAND at the terminal's width otherwise). The parser knows exactly this
// wording and declines anything else.
func psAuxScript(command ...string) model.Script {
	return model.Script{Run: "LC_ALL=C " + strings.Join(command, " "), Parse: parsePsAux}
}

// psAuxCells are the shapes of a row's cells before the command line, in column
// order: the account, the two percentages aux prints with one decimal, the two
// sizes, the terminal as procps names it, the state string, the start clock and
// the accumulated time. The header alone does not tell this table from another
// system's ps, so the dialect is what the parser reads to decline a foreign one.
var psAuxCells = []*regexp.Regexp{
	regexp.MustCompile(`^\S+$`),                                        // USER
	regexp.MustCompile(`^\d+$`),                                        // PID
	regexp.MustCompile(`^\d+(?:\.\d+)?$`),                              // %CPU
	regexp.MustCompile(`^\d+(?:\.\d+)?$`),                              // %MEM
	regexp.MustCompile(`^\d+$`),                                        // VSZ
	regexp.MustCompile(`^\d+$`),                                        // RSS
	regexp.MustCompile(`^(\?|pts/\d+|ttyS?\d*|console|ptmx|\d+:\d+)$`), // TTY
	regexp.MustCompile(`^[A-Za-z<>NslL+]+$`),                           // STAT
	regexp.MustCompile(`^(\d{1,2}:\d{2}|\d{4}|[A-Z][a-z]{2}\d{1,2})$`), // START
	regexp.MustCompile(`^\d+:\d{2}(:\d{2})?$`),                         // TIME
}

// parsePsAux reads an aux table: the header names the schema — the native
// tier's own columns, so a row's fields are spelled the same whichever source
// read it — and each row is the ten single-word cells followed by the command
// line, which is the rest of the line with its own blanks kept.
func parsePsAux(stdout string) (*model.RecordSet, error) {
	set := &model.RecordSet{Header: native.PsAuxColumns}
	headerSeen := false
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !headerSeen {
			if header := strings.Fields(line); !slices.Equal(header, native.PsAuxColumns) {
				return nil, fmt.Errorf("not a ps aux table: header %q", strings.Join(header, " "))
			}
			headerSeen = true
			continue
		}
		values, err := psAuxRow(line)
		if err != nil {
			return nil, err
		}
		fields := make([]model.Field, len(native.PsAuxColumns))
		for index, name := range native.PsAuxColumns {
			fields[index] = model.Field{Name: name, Value: values[index]}
		}
		set.Rows = append(set.Rows, model.Record{Fields: fields})
	}
	if !headerSeen {
		return nil, fmt.Errorf("the tier's text carries no ps aux header")
	}
	return set, nil
}

// psAuxRow cuts one row into the column values: the cells before the command
// line are single words, and the command line is everything after them.
func psAuxRow(line string) ([]string, error) {
	values := make([]string, 0, len(native.PsAuxColumns))
	rest := line
	for len(values) < len(native.PsAuxColumns)-1 {
		rest = strings.TrimLeft(rest, " ")
		cell, remainder, _ := strings.Cut(rest, " ")
		if cell == "" {
			return nil, fmt.Errorf("ps aux row has too few columns: %q", line)
		}
		values = append(values, cell)
		rest = remainder
	}
	command := strings.TrimSpace(rest)
	if command == "" {
		return nil, fmt.Errorf("ps aux row carries no command line: %q", line)
	}
	for index, cell := range psAuxCells {
		if !cell.MatchString(values[index]) {
			return nil, fmt.Errorf("ps aux row %q: %q is not this table's dialect", line, values[index])
		}
	}
	return append(values, command), nil
}
