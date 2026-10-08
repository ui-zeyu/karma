// Read is the pipeline's entry point: one body in, one document out. It picks
// the path the body's shape deserves, caps the text before joining it, and
// carries the channel's cut into the document.

package reader_test

import (
	"slices"
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

// stepLog is the reading's hooks noting what they read, in the order they read
// it. A hook that ran out of turn, or over another step's text, fails here
// rather than in a panel that quietly drew the wrong rows.
type stepLog []string

func (l *stepLog) note(step, text string) {
	*l = append(*l, step+"("+strings.ReplaceAll(text, "\n", `\n`)+")")
}

// loggingRule is a rule that states nothing and notes the record it judged.
type loggingRule struct{ log *stepLog }

func (loggingRule) Name() string { return "probe" }

func (r loggingRule) Judge(rec *model.Record) []model.Match {
	r.log.note("rule", rec.LineText())
	return nil
}

// The reading's order, pinned: the tier's join runs once over the whole body,
// then the body splits at its own titles, then each part is aligned and
// normalized under its own title, and only then do the rules read it. The
// title's own judgment comes with its part, after that part's shaping.
func TestReadRunsItsHooksInOrder(t *testing.T) {
	var log stepLog
	align := func(title, text string) *model.Shaped {
		log.note("align "+title, text)
		return &model.Shaped{Text: text}
	}
	body := model.Body{Sections: []model.BodySection{{
		Title:  "file",
		Titles: []string{"== part"},
		Text:   "raw\n",
		Assemble: func(text string) string {
			log.note("join", text)
			return text + "== part\n"
		},
		Adapt: align,
	}}}
	check := &model.Check{
		ID: "probe",
		Normalize: func(title, text string) *model.Shaped {
			log.note("normalize "+title, text)
			return &model.Shaped{Text: text}
		},
		Rules: []model.Matcher{loggingRule{&log}},
	}
	document := reader.Read(model.ReadRequest{Check: check, Body: body, Floor: model.FloorAll})
	want := []string{
		`join(raw\n)`,
		`align file(raw\n)`,
		`normalize file(raw\n)`,
		`rule(file)`,
		`rule(raw)`,
		`align == part()`,
		`normalize == part()`,
		`rule(== part)`,
	}
	if !slices.Equal(log, want) {
		t.Fatalf("the reading ran:\n%v\nwant:\n%v", log, want)
	}
	if got := keptText(document); len(got) != 1 || got[0] != "raw" {
		t.Fatalf("read body: %q", got)
	}
}

// The byte cap runs before the join, and a body the cap cut is not joined at
// all: the marked stream the join explains is the evidence, and half of a
// stream explains nothing.
func TestReadCapsBeforeJoining(t *testing.T) {
	var log stepLog
	body := model.Body{Sections: []model.BodySection{{
		Text:     strings.Repeat("x", 40) + "\n",
		Assemble: func(text string) string { log.note("join", text); return text },
	}}}
	document := reader.Read(model.ReadRequest{
		Check: &model.Check{ID: "probe", ScanBytes: 20},
		Body:  body, Floor: model.FloorAll,
	})
	if len(log) != 0 {
		t.Fatalf("a cut body is not joined: %v", log)
	}
	if !document.Truncated {
		t.Fatal("the cap marks the document cut")
	}
}
