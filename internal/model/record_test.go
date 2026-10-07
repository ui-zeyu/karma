package model

import (
	"strings"
	"testing"
)

// The line text is the record's values joined by a blank: the readable
// rendering a reader shows for evidence.
func TestRecordsText(t *testing.T) {
	rec := Record{Fields: []Field{{Value: "root"}, {Value: "2210"}, {Value: "/bin/sh"}}}
	if got := rec.LineText(); got != "root 2210 /bin/sh" {
		t.Errorf("line text = %q", got)
	}
	if got := RecordsText([]Record{rec, rec}); got != "root 2210 /bin/sh\nroot 2210 /bin/sh\n" {
		t.Errorf("records text = %q", got)
	}
	// A value holding the separator characters cannot confuse the text: they are
	// the record's own bytes, and only a channel has to flatten them.
	odd := Record{Fields: []Field{{Value: "one\ttwo"}}}
	if got := odd.LineText(); got != "one\ttwo" {
		t.Errorf("a tab inside a value = %q", got)
	}
}

// Fields are read by name, and a line of text is a record whose one field holds
// it: one input shape for every rule.
func TestRecordLookups(t *testing.T) {
	rec := Record{Fields: []Field{
		{Name: "USER", Value: "root"}, {Name: "COMMAND", Value: "bash -i"},
	}}
	if got, ok := rec.Value("COMMAND"); !ok || got != "bash -i" {
		t.Errorf("Value(COMMAND) = %q, %v", got, ok)
	}
	if index := rec.FieldIndex("COMMAND"); index != 1 {
		t.Errorf("FieldIndex(COMMAND) = %d", index)
	}
	if _, ok := rec.Value("UID"); ok {
		t.Error("a column the record lacks must not answer")
	}
	if index := rec.FieldIndex("UID"); index != -1 {
		t.Errorf("FieldIndex(UID) = %d, want -1", index)
	}
	if values := rec.Values(); strings.Join(values, ",") != "root,bash -i" {
		t.Errorf("Values = %v", values)
	}
	text := TextRecord("a line of text")
	if len(text.Fields) != 1 || text.LineText() != "a line of text" {
		t.Errorf("a line of text is a one-field record, got %+v", text)
	}
	if index := text.FieldIndex(""); index != 0 {
		t.Errorf("the text record's field is unnamed and first, got %d", index)
	}
}
