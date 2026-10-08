// fstab shaping: the six fields of a mount record become the columns the check's
// form draws, and every other line — a comment, a blank, a record a hand edit
// left half-written — becomes a record that states the line itself, which the
// form prints as the remark it is.

package shape

import (
	"strings"

	"karma/internal/model"
)

// FstabColumns is fstab(5)'s record as karma spells it: spec, mount point,
// filesystem type, options, dump frequency, pass number.
var FstabColumns = []string{"Device", "Mount point", "Type", "Options", "Dump", "Pass"}

// Fstab reads an fstab body into records. Both channels read the same file, so
// one shaping serves them both.
//
// A line that is not a six-field record keeps its own bytes as a one-value
// record: the file's comments are part of what it says, and the form draws such
// a record as the line it is rather than as a row with one cell filled. '#'
// opens a comment in fstab(5)'s own syntax — a comment may well split into six
// words, and those words are not a mount. A body with no record at all is
// declined whole, and the section stays the text as the file wrote it.
func Fstab(title, body string) *model.Shaped {
	rows := lines(body)
	set := &model.RecordSet{Header: FstabColumns}
	records := 0
	for _, row := range rows {
		fields := strings.Fields(row)
		if len(fields) == len(FstabColumns) && !strings.HasPrefix(fields[0], "#") {
			record := model.Record{Fields: make([]model.Field, len(FstabColumns))}
			for index, name := range FstabColumns {
				record.Fields[index] = model.Field{Name: name, Value: fields[index]}
			}
			set.Rows = append(set.Rows, record)
			records++
			continue
		}
		set.Rows = append(set.Rows, model.Record{
			Fields: []model.Field{{Value: strings.TrimSuffix(row, "\r")}},
		})
	}
	if records == 0 {
		return nil
	}
	return shapedRecords(strings.Join(rows, "\n")+"\n", set)
}
