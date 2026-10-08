// Read is the pipeline's entry point: one body in, one document out. It picks
// the path the body's shape deserves, runs the tier's own join over the text
// before anything caps it, and carries the channel's cut into the document.

package reader_test

import (
	"strings"
	"testing"

	"karma/internal/model"
	"karma/internal/reader"
)

// The tier's dialect alignment runs before the check's own normalization, each
// seeing what the step before it produced, and the channel's cut lands on the
// document.
func TestReadAlignsTheDialectThenNormalizes(t *testing.T) {
	check := &model.Check{
		ID: "probe",
		Normalize: func(_, body string) *model.Shaped {
			if body != "aligned" {
				t.Fatalf("the check's normalizer reads the tier's alignment, got %q", body)
			}
			return &model.Shaped{Text: "normalized"}
		},
	}
	adapt := func(_, body string) *model.Shaped {
		if body != "raw" {
			t.Fatalf("the tier's alignment reads the raw body, got %q", body)
		}
		return &model.Shaped{Text: "aligned"}
	}
	document := reader.Read(model.ReadRequest{
		Check: check,
		Body:  model.Body{Sections: []model.BodySection{{Text: "raw", Adapt: adapt}}},
		Floor: model.FloorAll, Truncated: true,
	})
	if got := keptText(document); len(got) != 1 || got[0] != "normalized" {
		t.Fatalf("read body: %q", got)
	}
	if !document.Truncated {
		t.Fatal("the channel's cut belongs on the document")
	}
}

// The tier's own join runs before the reading shapes anything, so a marked stream
// the join explains is read as the rows it states.
func TestReadJoinsTheSectionStreamFirst(t *testing.T) {
	body := model.Body{Sections: []model.BodySection{{
		Text:     "HIDDEN x\n",
		Assemble: func(text string) string { return strings.TrimSpace(text) + " rows\n" },
	}}}
	document := reader.Read(model.ReadRequest{
		Check: &model.Check{ID: "probe"}, Body: body, Floor: model.FloorAll,
	})
	if got := keptText(document); len(got) != 1 || got[0] != "HIDDEN x rows" {
		t.Fatalf("the join runs before the reading: %q", got)
	}
}

// fieldsRead is a process table of three rows, handed to the reading as fields.
func fieldsRead(t *testing.T, floor model.SeverityFloor) model.Document {
	t.Helper()
	set := model.RecordSet{
		Header: []string{"PID", "CMD"},
		Rows: []model.Record{
			{Fields: []model.Field{{Value: "1"}, {Value: "== a title, not a section"}}},
			{Fields: []model.Field{{Value: "2"}, {Value: "/sbin/init"}}},
			{Fields: []model.Field{{Value: "3"}, {Value: "/bin/sh"}}},
		},
	}
	check := &model.Check{
		ID: "ps",
		Rules: []model.Matcher{
			rule("init", `/sbin/init`, model.High),
			rule("shell", `/bin/sh$`, model.Low),
		},
	}
	return reader.Read(model.ReadRequest{Check: check,
		Body: model.Body{Sections: []model.BodySection{{Records: &set}}}, Floor: floor})
}

// A body that arrived as fields takes the records path: one section, the set's
// columns, no section split — a field that looks like a title stays a field.
func TestReadReadsFieldsWithoutSplitting(t *testing.T) {
	document := fieldsRead(t, model.FloorAll)
	if len(document.Sections) != 1 {
		t.Fatalf("fields are one section: %+v", document.Sections)
	}
	section := document.Sections[0]
	if section.Title != "" || len(section.Columns) != 2 {
		t.Fatalf("no title, the set's own columns: %+v", section)
	}
	if got := keptText(document); len(got) != 3 || got[0] != "1 == a title, not a section" {
		t.Fatalf("kept rows: %q", got)
	}
	severities := []model.Severity{model.Info, model.High, model.Low}
	for index, want := range severities {
		if got := section.Lines[index].Severity; got != want {
			t.Fatalf("row %d is %v, want %v", index, got, want)
		}
	}
}

// The run's floor reads the records path the way it reads the text path: below
// the floor is counted and left out.
func TestReadAppliesTheFloorToFields(t *testing.T) {
	document := fieldsRead(t, model.FloorAbove(model.Low))
	if got := keptText(document); len(got) != 2 {
		t.Fatalf("the floor keeps the findings: %q", got)
	}
	if got := hiddenBelow(document); got != 1 {
		t.Fatalf("the floor hid %d rows, want the quiet one", got)
	}
}
