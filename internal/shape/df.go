// df shaping: `df`'s table — a header line and one row per mounted filesystem —
// read into the columns the panel draws, so the reading keeps the six cells and
// the form lays them out instead of a lexer re-splitting the tool's spacing.

package shape

import (
	"strings"

	"karma/internal/model"
)

// DfColumns is df's table as karma spells it: the check's form and the records
// a row is read into both name these, so a row reads the same whichever df
// collected it.
var DfColumns = []string{"Filesystem", "Size", "Used", "Avail", "Use%", "Mounted on"}

// Df reads a df body into records: the header states the table (see isDfHeader
// for what makes a line df's header), and every line after it is one
// filesystem's six cells.
//
// A body the reading cannot use whole is declined whole — a row with fewer
// cells than the table, and a table with no rows under its header, both return
// nil rather than a fragment of one table drawn as if it were the table.
func Df(title, body string) *model.Shaped {
	rows := lines(body)
	if len(rows) < 2 || !isDfHeader(rows[0]) {
		return nil
	}
	set := &model.RecordSet{Header: DfColumns}
	var text strings.Builder
	for _, row := range rows[1:] {
		cells, ok := dfCells(row)
		if !ok {
			return nil
		}
		fields := make([]model.Field, len(DfColumns))
		for index, name := range DfColumns {
			fields[index] = model.Field{Name: name, Value: cells[index]}
		}
		set.Rows = append(set.Rows, model.Record{Fields: fields})
		text.WriteString(row)
		text.WriteByte('\n')
	}
	// The header line is the form's to draw, so the text the reading walks is
	// the rows alone: one line per record, which is what the reading checks
	// before it hands a section to a form.
	return shapedRecords(text.String(), set)
}

// isDfHeader reports whether a line is df's header: the name first, "Mounted
// on" last, and the four cells between them. Those four are not read, because
// every df spells them its own way — GNU's -h prints Size/Used/Avail/Use%, its
// -P 1024-blocks/Used/Available/Capacity, busybox Size/Used/Available/Use% —
// while the row under them is the same six columns in each.
//
// The count is the bound that keeps a foreign table out: six cells, or seven
// with "Mounted on" counted twice. BSD's own df -h names ten — it carries
// iused/ifree/%iused — and that table has columns karma does not draw, so it is
// declined and reaches the panel as the tool wrote it.
func isDfHeader(line string) bool {
	cells := strings.Fields(line)
	if len(cells) != len(DfColumns) && len(cells) != len(DfColumns)+1 {
		return false
	}
	if cells[0] != DfColumns[0] {
		return false
	}
	return cells[len(cells)-2] == "Mounted" && cells[len(cells)-1] == "on"
}

// dfCells cuts one df row into the table's six cells: the first five are single
// words and the last — the mount point — is the rest of the line, because a
// mount point may carry a blank. A row with a cell missing is not this table's.
func dfCells(line string) ([]string, bool) {
	cells := make([]string, 0, len(DfColumns))
	rest := strings.TrimLeft(line, " ")
	for range len(DfColumns) - 1 {
		cell, remainder, _ := strings.Cut(rest, " ")
		if cell == "" {
			return nil, false
		}
		cells = append(cells, cell)
		rest = strings.TrimLeft(remainder, " ")
	}
	point := strings.TrimRight(rest, " \r")
	if point == "" {
		return nil, false
	}
	return append(cells, point), true
}
