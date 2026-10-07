// The sh source's call at the session boundary: a Script tier's pinned command
// runs like a Shell and answers with the records its parser states.

package session

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"karma/internal/model"
)

// wordsParser reads whitespace-separated rows as two fields, the smallest shape
// a Script tier's parser can have.
func wordsParser(stdout string) (*model.RecordSet, error) {
	set := &model.RecordSet{Header: []string{"ONE", "TWO"}}
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		parts := strings.Fields(line)
		if len(parts) != 2 {
			return nil, errors.New("not a two-word row: " + line)
		}
		set.Rows = append(set.Rows, model.Record{Fields: []model.Field{
			{Name: "ONE", Value: parts[0]},
			{Name: "TWO", Value: parts[1]},
		}})
	}
	return set, nil
}

func TestRunScriptAnswersWithRecords(t *testing.T) {
	script := model.Script{Run: `printf 'a b\nc d\n'`, Parse: wordsParser}
	result := runCall(context.Background(), LocalSession{}, script, 10*time.Second, model.RowCap{})
	if result.Verdict != model.VerdictAnswered {
		t.Fatalf("the Script tier should answer: %+v", result)
	}
	if result.Records == nil || len(result.Records.Rows) != 2 {
		t.Fatalf("records = %+v, want two rows", result.Records)
	}
	if got, _ := result.Records.Rows[1].Value("TWO"); got != "d" {
		t.Errorf("second row TWO = %q, want d", got)
	}
	// A records answer carries no text form: nothing formats the fields into
	// lines for another layer to parse back out.
	if result.Stdout != "" {
		t.Errorf("the text should not survive the parse: %q", result.Stdout)
	}
}

// A cap bounds the records after the parse, the way it bounds a Fields tier's.
func TestRunScriptCapBoundsTheRecords(t *testing.T) {
	script := model.Script{Run: `printf 'a b\nc d\ne f\n'`, Parse: wordsParser}
	result := runCall(context.Background(), LocalSession{}, script, 10*time.Second, model.Scan(2))
	if result.Verdict != model.VerdictAnswered || !result.Truncated {
		t.Fatalf("a capped walk is the tier's answer, marked cut: %+v", result)
	}
	if len(result.Records.Rows) != 2 {
		t.Fatalf("rows = %d, want the cap's two", len(result.Records.Rows))
	}
}

// headedParser reads the same two-word rows as wordsParser, after one header
// line. The header is how a tool's table (ps aux) spends a text line that is
// not a record.
func headedParser(stdout string) (*model.RecordSet, error) {
	head, rest, ok := strings.Cut(strings.TrimSpace(stdout), "\n")
	if !ok || head != "HEADER" {
		return nil, errors.New("missing header")
	}
	return wordsParser(rest)
}

// The row cap counts records, so the tool's header does not consume one of
// them. A shape cap is the tier's own answer: the panel is not told the body
// was cut.
func TestRunScriptCapCountsRecordsPastTheHeader(t *testing.T) {
	script := model.Script{Run: `printf 'HEADER\na b\nc d\ne f\n'`, Parse: headedParser}
	result := runCall(context.Background(), LocalSession{}, script, 10*time.Second, model.Shape(2))
	if result.Verdict != model.VerdictAnswered || result.Truncated {
		t.Fatalf("a shape cap is the whole answer: %+v", result)
	}
	if result.Records == nil || len(result.Records.Rows) != 2 {
		t.Fatalf("rows = %+v, want the cap's two records past the header", result.Records)
	}
}

// Text the parser does not recognize fails the tier rather than passing a
// fragment off as an answer; a parser that panics fails it the same way.
func TestRunScriptRefusesTextItCannotRead(t *testing.T) {
	refusing := model.Script{Run: `printf 'one\n'`, Parse: wordsParser}
	result := runCall(context.Background(), LocalSession{}, refusing, 10*time.Second, model.RowCap{})
	if result.Verdict != model.VerdictFailed || !strings.Contains(result.Stderr, "two-word") {
		t.Fatalf("a refusal should fail the tier with the parser's own words: %+v", result)
	}

	panicking := model.Script{Run: `printf 'a b\n'`, Parse: func(string) (*model.RecordSet, error) {
		panic("parser blew up")
	}}
	result = runCall(context.Background(), LocalSession{}, panicking, 10*time.Second, model.RowCap{})
	if result.Verdict != model.VerdictFailed || !strings.Contains(result.Stderr, "script parse") {
		t.Fatalf("a panicking parser should fail one tier, naming the boundary: %+v", result)
	}
}

// A command the host does not have is the missing-binary 127: the tier is
// unavailable, and its parser never runs.
func TestRunScriptMissingCommandIsUnavailable(t *testing.T) {
	script := model.Script{Run: "karma-there-is-no-such-command", Parse: func(string) (*model.RecordSet, error) {
		t.Error("the parser should not run for a command that never started")
		return nil, nil
	}}
	result := runCall(context.Background(), LocalSession{}, script, 10*time.Second, model.RowCap{})
	if result.Verdict != model.VerdictUnavailable || result.ExitCode != 127 {
		t.Fatalf("a missing command should read as unavailable: %+v", result)
	}
	// And the typed check the runner makes: Unavailable does not settle a walk.
	if result.Verdict.Settled() {
		t.Errorf("unavailable must not settle the walk: %v", result.Verdict)
	}
}

// A remote channel cannot run an in-process body: it answers unavailable, which
// is what falls through on a channel that drives the target's shell instead.
func TestRemoteChannelsRefuseInProcessBodies(t *testing.T) {
	call := model.Call{Inv: model.Fields{Read: func(context.Context) (*model.RecordSet, error) {
		return &model.RecordSet{}, nil
	}}}
	result := noShellFor(call.Inv)
	if result.Verdict != model.VerdictUnavailable || result.ExitCode != 127 {
		t.Fatalf("in-process bodies are unavailable off their own host: %+v", result)
	}
}
