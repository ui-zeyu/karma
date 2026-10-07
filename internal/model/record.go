// Records: a body that arrives as fields rather than as text.
//
// A collection that reads a kernel interface already holds every value it
// prints — pid, user, state, command line — and the text it used to format them
// into was read back by the rules and by the panel's lexers. A record carries
// the fields themselves: the reading layer hands them to the rules, and the
// form a check declares lays them out. Nothing formats fields into text to
// parse them back out.

package model

import "strings"

// Field is one cell of a record: the column's name (empty until the record set
// supplies it) and the value as the collection would print it. The value
// carries the tool's own spelling and none of the layout: `%4.1f` stays a
// two-character "0.0" and the width that padded it is the form's business.
type Field struct {
	Name  string
	Value string
}

// Record is one row: its fields in column order.
type Record struct {
	Fields []Field
}

// RecordSet is a structured body: the column names and the records, in the
// order the collection read them. Header is the panel's head, so it is not one
// of the rows — it travels with them as the schema they are read by.
type RecordSet struct {
	Header []string
	Rows   []Record
}

// Value returns the first field named name; ok is false when the record has no
// such column.
func (r Record) Value(name string) (string, bool) {
	index := r.FieldIndex(name)
	if index < 0 {
		return "", false
	}
	return r.Fields[index].Value, true
}

// FieldIndex is the index of the column named name, or -1 when the record has
// no such column.
func (r Record) FieldIndex(name string) int {
	for index, field := range r.Fields {
		if field.Name == name {
			return index
		}
	}
	return -1
}

// LineText is the record as one line: its values joined by a blank. It is the
// readable rendering of a row — the evidence line and the fallback panels show
// it — and no rule reads it back.
func (r Record) LineText() string { return strings.Join(r.Values(), " ") }

// Values is the record's cell values in column order.
func (r Record) Values() []string {
	values := make([]string, len(r.Fields))
	for index, field := range r.Fields {
		values[index] = field.Value
	}
	return values
}

// TextRecord is a line of text as a record: one field holding the whole line.
// A body with no fields of its own — a log, a config file, a history — is read
// as a series of those, so rules and filters have one input shape whatever the
// body is.
func TextRecord(line string) Record {
	return Record{Fields: []Field{{Value: line}}}
}

// RecordsText is the records' line text, one line per record: what a fallback
// panel or an evidence line shows a tier that answered with fields.
func RecordsText(rows []Record) string {
	var b strings.Builder
	for _, rec := range rows {
		b.WriteString(rec.LineText())
		b.WriteByte('\n')
	}
	return b.String()
}
