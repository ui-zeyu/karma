// The --json run: the result stream leaves the process instead of a drawn
// report, one object per check as it finishes.

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"karma/internal/collect"
	"karma/internal/model"
	"karma/internal/session"
)

// jsonCatalog is a stand-in catalog whose tiers answer from this process: one
// walk that answers, one whose only tier the host lacks.
func jsonCatalog() []*model.Check {
	return []*model.Check{
		{
			ID: "demo", Title: "Demo", Aspect: model.AspectSystem, Platform: model.Linux,
			Steps: []model.Step{{{Label: "native", Inv: model.Native{
				Body: func(context.Context) (string, error) { return "== a\none two\n", nil },
			}}}},
			Rules: []model.Matcher{model.NewRule("two", `two`, model.High, "a two")},
		},
		{
			ID: "absent", Title: "Absent", Aspect: model.AspectKernel, Platform: model.Linux,
			Steps: []model.Step{{{Label: "gone", Inv: model.Native{
				Body: func(context.Context) (string, error) { return "", model.ErrTierUnavailable },
			}}}},
		},
	}
}

// errWriter is a report stream that cannot be written: the pipe is gone.
type errWriter struct{}

var errNoPipe = errors.New("broken pipe")

func (errWriter) Write([]byte) (int, error) { return 0, errNoPipe }

func jsonRun(t *testing.T, w io.Writer) error {
	t.Helper()
	options := model.RunOptions{Concurrency: 2, Timeout: 5 * time.Second, JSON: true}
	return Execute(context.Background(), w, io.Discard, session.LocalTransport{}, options, jsonCatalog())
}

// A --json run writes the checks' results and nothing else: no masthead, no
// panel, one decodable object per check.
func TestJSONRunWritesOneObjectPerCheck(t *testing.T) {
	var out bytes.Buffer
	if err := jsonRun(t, &out); err != nil {
		t.Fatalf("the run failed: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("one line per check, got %d:\n%s", len(lines), out.String())
	}
	seen := map[string]collect.Result{}
	for _, line := range lines {
		var result collect.Result
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			t.Fatalf("line %q is not one result: %v", line, err)
		}
		seen[result.Check] = result
	}
	answered, ok := seen["demo"]
	if !ok || answered.Outcome != model.Collected.String() || answered.Probe != "native" ||
		answered.Raw != "== a\none two\n" {
		t.Fatalf("the answered check travelled as %+v", answered)
	}
	if absent := seen["absent"]; absent.Outcome != model.Skipped.String() ||
		!strings.Contains(strings.Join(absent.Skipped, ","), "gone") {
		t.Fatalf("the skipped check travelled as %+v", absent)
	}
	// The report itself is not printed: no header line, no panel rail.
	if strings.Contains(out.String(), "KARMA") || strings.Contains(out.String(), "▌") {
		t.Fatalf("a --json run draws nothing:\n%s", out.String())
	}
}

// The stream that cannot be written is the run's own failure: a reader missing a
// result has to be told, not handed a short stream.
func TestJSONRunReportsAStreamItCouldNotWrite(t *testing.T) {
	err := jsonRun(t, errWriter{})
	var coded exitError
	if !errors.As(err, &coded) || coded.code != ExitRead {
		t.Fatalf("a failed stream should be an ExitRead failure, got %v", err)
	}
	if !strings.Contains(err.Error(), errNoPipe.Error()) {
		t.Fatalf("the message should say what happened to the stream: %v", err)
	}
}

// The switch is a run option on every collecting command, and reading it back
// needs no selector.
func TestRunFlagsCarryTheJSONSwitch(t *testing.T) {
	cmd := newLocalCmd()
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatal(err)
	}
	options, err := runOptions(cmd.Flags(), nil)
	if err != nil {
		t.Fatalf("the flags should read: %v", err)
	}
	if !options.JSON {
		t.Fatal("--json should reach the run options")
	}
	plain, err := runOptions(newLocalCmd().Flags(), nil)
	if err != nil {
		t.Fatalf("the flags should read: %v", err)
	}
	if plain.JSON {
		t.Fatal("a command line without --json draws the report")
	}
}
