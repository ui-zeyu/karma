// The ps command's sh tier: the pinned spelling the sh source runs, and the
// parser that reads it back into the native tier's schema. This is the first
// Script tier — the command is the schema, and the parse is karma's code.

package linux

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

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
var psEfScript = model.Script{Run: "LC_ALL=C ps -efww", Parse: parsePsEf}

// psEfCells are the shapes of a row's cells before the command line, in column
// order: the two links and the cpu tick, STIME as procps spells it (a clock for
// a start today, the month and day for an earlier one, a year for an older one),
// a terminal as procps names it, and the accumulated time. A header alone does
// not tell this table from another system's ps — BSD's `ps -ef` prints the same
// eight names with "29Sep26", "??" and "100:14.77" under them — so the dialect is
// what the parser reads to decline a foreign one.
var psEfCells = []*regexp.Regexp{
	regexp.MustCompile(`^\d+$`),                                        // PID
	regexp.MustCompile(`^\d+$`),                                        // PPID
	regexp.MustCompile(`^\d+$`),                                        // C
	regexp.MustCompile(`^(\d{1,2}:\d{2}|\d{4}|[A-Z][a-z]{2}\d{1,2})$`), // STIME
	regexp.MustCompile(`^(\?|pts/\d+|ttyS?\d*|console|ptmx|\d+:\d+)$`), // TTY
	regexp.MustCompile(`^\d+:\d{2}(:\d{2})?$`),                         // TIME
}

// parsePsEf reads `ps -ef`'s table. The header names the schema — the native
// tier's own columns, so a row's fields are spelled the same whichever source
// read it — and each row is the seven single-word cells followed by the command
// line, which is the rest of the line with its own blanks kept.
func parsePsEf(stdout string) (*model.RecordSet, error) {
	set := &model.RecordSet{Header: native.PsEfColumns}
	headerSeen := false
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !headerSeen {
			if header := strings.Fields(line); !slices.Equal(header, native.PsEfColumns) {
				return nil, fmt.Errorf("not a ps -ef table: header %q", strings.Join(header, " "))
			}
			headerSeen = true
			continue
		}
		values, err := psEfRow(line)
		if err != nil {
			return nil, err
		}
		fields := make([]model.Field, len(native.PsEfColumns))
		for index, name := range native.PsEfColumns {
			fields[index] = model.Field{Name: name, Value: values[index]}
		}
		set.Rows = append(set.Rows, model.Record{Fields: fields})
	}
	if !headerSeen {
		return nil, fmt.Errorf("the tier's text carries no ps -ef header")
	}
	return set, nil
}

// psEfRow cuts one row into the column values: the cells before the command
// line are single words, and the command line is everything after them.
func psEfRow(line string) ([]string, error) {
	values := make([]string, 0, len(native.PsEfColumns))
	rest := line
	for len(values) < len(native.PsEfColumns)-1 {
		rest = strings.TrimLeft(rest, " ")
		cell, remainder, _ := strings.Cut(rest, " ")
		if cell == "" {
			return nil, fmt.Errorf("ps -ef row has too few columns: %q", line)
		}
		values = append(values, cell)
		rest = remainder
	}
	command := strings.TrimSpace(rest)
	if command == "" {
		return nil, fmt.Errorf("ps -ef row carries no command line: %q", line)
	}
	// The cells before the command line carry this dialect: the two links the
	// tree nests on, and the shapes that tell procps's table from another
	// system's.
	for index, cell := range psEfCells {
		if !cell.MatchString(values[1+index]) {
			return nil, fmt.Errorf("ps -ef row %q: %q is not this table's dialect", line, values[1+index])
		}
	}
	return append(values, command), nil
}
