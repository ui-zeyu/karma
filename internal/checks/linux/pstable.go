// The pinned ps tables' shared reading: the header names the schema, the row is
// the single-word cells followed by the command line, and the cells' shapes are
// the dialect that tells this table from another system's.
//
// It is one reader because it is one algorithm: the System V table `ps -ef`
// prints and the aux table `ps aux` prints differ in their columns and in the
// shapes those columns carry, and in nothing else. Each table states its own
// columns and dialect here and the reading refuses anything else — a busybox
// ps, a BSD ps whose header means something other than its rows.

package linux

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"karma/internal/model"
)

// psSchema is one pinned ps table: the schema its header names — the native
// tier's own columns, so a row's fields are spelled the same whichever source
// read it — and the dialect its cells carry.
type psSchema struct {
	// name is how the text calls itself in a refusal ("ps -ef").
	name    string
	columns []string
	// dialects are the shapes of the cells between the account column and the
	// command line, in column order. The account cell is ps's own eight-cell
	// cut of a name and is not a shape to judge.
	dialects []*regexp.Regexp
}

// parse reads the table: the header line states the schema, every row after it
// is the cells followed by the command line.
func (t psSchema) parse(stdout string) (*model.RecordSet, error) {
	set := &model.RecordSet{Header: t.columns}
	headerSeen := false
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !headerSeen {
			if header := strings.Fields(line); !slices.Equal(header, t.columns) {
				return nil, fmt.Errorf("not a %s table: header %q", t.name, strings.Join(header, " "))
			}
			headerSeen = true
			continue
		}
		values, err := t.row(line)
		if err != nil {
			return nil, err
		}
		fields := make([]model.Field, len(t.columns))
		for index, name := range t.columns {
			fields[index] = model.Field{Name: name, Value: values[index]}
		}
		set.Rows = append(set.Rows, model.Record{Fields: fields})
	}
	if !headerSeen {
		return nil, fmt.Errorf("the tier's text carries no %s header", t.name)
	}
	return set, nil
}

// row cuts one row into the column values: the cells before the command line
// are single words, and the command line is everything after them, its own
// blanks kept.
func (t psSchema) row(line string) ([]string, error) {
	values := make([]string, 0, len(t.columns))
	rest := line
	for len(values) < len(t.columns)-1 {
		rest = strings.TrimLeft(rest, " ")
		cell, remainder, _ := strings.Cut(rest, " ")
		if cell == "" {
			return nil, fmt.Errorf("%s row has too few columns: %q", t.name, line)
		}
		values = append(values, cell)
		rest = remainder
	}
	command := strings.TrimSpace(rest)
	if command == "" {
		return nil, fmt.Errorf("%s row carries no command line: %q", t.name, line)
	}
	for index, dialect := range t.dialects {
		if !dialect.MatchString(values[1+index]) {
			return nil, fmt.Errorf("%s row %q: %q is not this table's dialect", t.name, line, values[1+index])
		}
	}
	return append(values, command), nil
}
