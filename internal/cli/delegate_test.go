// The delegated run: one call to the collector on the target, whose result
// stream is read while it happens.

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"karma/internal/collect"
	"karma/internal/model"
	"karma/internal/session"
)

// streamTransport opens a session that replays a prepared stream instead of
// running anything.
type streamTransport struct {
	sess session.Session
}

func (t streamTransport) Platform() model.Platform { return model.Linux }

func (t streamTransport) Open(context.Context) (session.Session, error) { return t.sess, nil }

// streamSession is a remote channel that answers a streamed call with a prepared
// stream: it records the invocation it was handed and hands back the lines the
// test scripted. Its Run fails, so a test that took the walk instead of the
// stream says so.
type streamSession struct {
	mu       sync.Mutex
	calls    []model.Invocation
	lines    []string
	result   model.RunResult
	cancelAt int // cancel the run after this many lines (0: never)
	cancel   context.CancelFunc
	emitted  int
}

func (s *streamSession) Name() string           { return "ssh" }
func (s *streamSession) Describe() string       { return "ssh lab@host" }
func (s *streamSession) Channel() model.Channel { return model.ChanSSH }
func (s *streamSession) Close() error           { return nil }

func (s *streamSession) Run(context.Context, model.Call) model.RunResult {
	return model.RunResult{Verdict: model.VerdictFailed, Stderr: "the delegated run streams"}
}

func (s *streamSession) Stream(ctx context.Context, call model.Call, each func(string)) model.RunResult {
	s.mu.Lock()
	s.calls = append(s.calls, call.Inv)
	cancelAt, cancel := s.cancelAt, s.cancel
	s.mu.Unlock()
	for _, line := range s.lines {
		each(line)
		s.mu.Lock()
		s.emitted++
		done := cancelAt > 0 && s.emitted >= cancelAt
		s.mu.Unlock()
		if done && cancel != nil {
			// The operator's own signal arrives mid-stream, the way Ctrl-C does.
			cancel()
			return model.RunResult{Verdict: model.VerdictInterrupted, ExitCode: -1}
		}
	}
	return s.result
}

func (s *streamSession) invocation(t *testing.T) []string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.calls) != 1 {
		t.Fatalf("a delegated run is one call, got %d", len(s.calls))
	}
	command, ok := s.calls[0].(model.Command)
	if !ok {
		t.Fatalf("the collector is called as a command, got %T", s.calls[0])
	}
	return command.Argv
}

// delegableSession is a target that takes a collector — placement's own fake,
// which answers uname, the home directory, the hash question and the upload —
// and answers the collector's call with a prepared stream.
type delegableSession struct {
	*placedSession
	stream *streamSession
}

func (s *delegableSession) Stream(ctx context.Context, call model.Call, each func(string)) model.RunResult {
	return s.stream.Stream(ctx, call, each)
}

// recordObserver keeps what the run handed it, in arrival order.
type recordObserver struct {
	results []*model.CheckResult
	started int
}

func (o *recordObserver) CheckStarted(*model.Check) { o.started++ }

func (o *recordObserver) CheckFinished(_ *model.Check, result *model.CheckResult) {
	o.results = append(o.results, result)
}

func (o *recordObserver) Damaged(*model.Check, error) {}

// streamed builds the protocol lines a collector would print for these checks.
func streamed(t *testing.T, results ...*model.CheckResult) []string {
	t.Helper()
	lines := make([]string, 0, len(results))
	for _, result := range results {
		line, err := collect.Of(result).Line()
		if err != nil {
			t.Fatalf("the line could not be built: %v", err)
		}
		lines = append(lines, string(line))
	}
	return lines
}

// collectedResult is one check's result as the collector's own run produces it.
func collectedResult(check *model.Check, probe, raw string) *model.CheckResult {
	return &model.CheckResult{
		Check:      check,
		ProbeLabel: probe,
		Outcome:    model.Collected,
		Raw:        raw,
	}
}

func delegateOptions() model.RunOptions {
	return model.RunOptions{Concurrency: 2, Timeout: 5 * time.Second}
}

// A delegated run is one call, and the call carries what the collector needs to
// run the same selection with the same bounds: the placement the channel did
// first, then the collector's own local JSON run.
func TestDelegatedRunAsksTheCollectorForTheSelection(t *testing.T) {
	catalog := jsonCatalog()
	stream := &streamSession{
		lines:  streamed(t, collectedResult(catalog[0], "native", "== a\none two\n")),
		result: model.RunResult{Verdict: model.VerdictAnswered, ExitCode: 0},
	}
	sess := &delegableSession{placedSession: newPlacedSession(), stream: stream}
	options := delegateOptions()
	options.Selectors = []string{"demo"}

	var out bytes.Buffer
	if err := Execute(context.Background(), &out, io.Discard, streamTransport{sess}, options, catalog); err != nil {
		t.Fatalf("the run failed: %v", err)
	}
	// The collector is the copy this run placed, asked for a local JSON run of
	// the same selection with the same bounds.
	argv := stream.invocation(t)
	if got, want := argv[0], "/home/ops/.karma/karma"; got != want {
		t.Fatalf("the collector was called at %q, want %q", got, want)
	}
	if got, want := strings.Join(argv[1:], " "), "local --json --timeout 5 --concurrency 2 demo"; got != want {
		t.Fatalf("the collector was called with %q, want %q", got, want)
	}
	// The report is drawn from the stream: the rule's hit is in the panel.
	if !strings.Contains(out.String(), "DEMO") {
		t.Fatalf("the panel from the stream is missing:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "⟨a two⟩") {
		t.Fatalf("the rule should have fired on the streamed text:\n%s", out.String())
	}
}

// A stream that is cut mid-run keeps the panels that arrived, and the run reports
// how many checks are missing.
func TestDelegatedRunKeepsThePartialReportOnACut(t *testing.T) {
	catalog := jsonCatalog()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &streamSession{
		lines:    streamed(t, collectedResult(catalog[0], "native", "== a\none two\n")),
		result:   model.RunResult{Verdict: model.VerdictAnswered, ExitCode: 0},
		cancelAt: 1,
		cancel:   cancel,
	}
	var (
		out      bytes.Buffer
		observer recordObserver
	)
	summary, err := runDelegated(ctx, stream, "/root/.karma/karma", catalog, delegateOptions(), &observer, &out)
	if err != nil {
		t.Fatalf("a cut run is not a failure of the collector: %v", err)
	}
	if !summary.Interrupted || summary.Results != 1 {
		t.Fatalf("the summary should say one result arrived and the run was cut: %+v", summary)
	}
	if len(observer.results) != 1 || observer.results[0].Check.ID != "demo" {
		t.Fatalf("the panel of the check that arrived should be drawn: %+v", observer.results)
	}
	// The document the operator read for itself is the one a local run would have
	// drawn: the rule fired on the tier's own text.
	if got := observer.results[0].Document.Sections[0].Lines[0].Severity; got != model.High {
		t.Fatalf("the streamed text should be read by the check's own rules, got %v", got)
	}
}

// A collector that stopped on its own is an environment failure, and its own
// words are the account of why.
func TestDelegatedRunReportsACollectorThatFailed(t *testing.T) {
	stream := &streamSession{result: model.RunResult{
		Verdict:  model.VerdictFailed,
		Stderr:   "karma: internal error in check demo: the walk blew up\n",
		ExitCode: 70,
	}}
	var observer recordObserver
	_, err := runDelegated(context.Background(), stream, "/root/.karma/karma", jsonCatalog(),
		delegateOptions(), &observer, io.Discard)
	var coded exitError
	if !errors.As(err, &coded) || coded.code != ExitEnvironment {
		t.Fatalf("a failed collector should be an environment failure, got %v", err)
	}
	for _, want := range []string{"exit status 70", "internal error in check demo"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the message should carry %q: %v", want, err)
		}
	}
}

// A stream that stops with exit 0 and checks missing would otherwise render as a
// report with silent holes.
func TestDelegatedRunReportsAStreamThatEndedEarly(t *testing.T) {
	catalog := jsonCatalog()
	stream := &streamSession{
		lines:  streamed(t, collectedResult(catalog[0], "native", "== a\none two\n")),
		result: model.RunResult{Verdict: model.VerdictAnswered, ExitCode: 0},
	}
	var observer recordObserver
	_, err := runDelegated(context.Background(), stream, "/root/.karma/karma", catalog,
		delegateOptions(), &observer, io.Discard)
	var coded exitError
	if !errors.As(err, &coded) || coded.code != ExitEnvironment {
		t.Fatalf("a short stream should be a failure, got %v", err)
	}
	if !strings.Contains(err.Error(), "after 1 of the 2 selected checks") {
		t.Fatalf("the message should say what arrived: %v", err)
	}
}

// The collector prints karma's own messages on its stderr, and they belong on
// this end's warning stream.
func TestDelegatedRunForwardsTheCollectorsOwnWords(t *testing.T) {
	catalog := jsonCatalog()
	stream := &streamSession{
		lines: streamed(t,
			collectedResult(catalog[0], "native", "== a\none two\n"),
			collectedResult(catalog[1], "", ""),
		),
		result: model.RunResult{
			Verdict:  model.VerdictAnswered,
			Stderr:   "karma: the capability probe timed out\n",
			ExitCode: 0,
		},
	}
	var (
		warn     bytes.Buffer
		observer recordObserver
	)
	if _, err := runDelegated(context.Background(), stream, "/root/.karma/karma", catalog,
		delegateOptions(), &observer, &warn); err != nil {
		t.Fatalf("the run failed: %v", err)
	}
	if !strings.Contains(warn.String(), "the capability probe timed out") {
		t.Fatalf("the collector's warning should travel: %q", warn.String())
	}
}

// A line this side cannot read is a warning rather than a failure: the collector
// is the same build, so a line that does not read means something outside the
// protocol happened to it.
func TestDelegatedRunWarnsAboutALineItCannotRead(t *testing.T) {
	catalog := jsonCatalog()
	stream := &streamSession{
		lines: append(streamed(t,
			collectedResult(catalog[0], "native", "== a\none two\n"),
			collectedResult(catalog[1], "", ""),
		), "{half a line"),
		result: model.RunResult{Verdict: model.VerdictAnswered, ExitCode: 0},
	}
	var (
		warn     bytes.Buffer
		observer recordObserver
	)
	if _, err := runDelegated(context.Background(), stream, "/root/.karma/karma", catalog,
		delegateOptions(), &observer, &warn); err != nil {
		t.Fatalf("an unreadable line is not the run's failure: %v", err)
	}
	if !strings.Contains(warn.String(), "could not be read") {
		t.Fatalf("the stream should say what it could not read: %q", warn.String())
	}
	if len(observer.results) != 2 {
		t.Fatalf("the readable lines should still be drawn: %d results", len(observer.results))
	}
}

// The operator's own bound is the collector's arithmetic: one budget per check,
// batched, plus one more for the channel's setup and the final read.
func TestCollectionBudgetIsTheWalkWorstCase(t *testing.T) {
	options := model.RunOptions{Timeout: 30 * time.Second, Concurrency: 6}
	if got, want := collectionBudget(76, options), 14*30*time.Second; got != want {
		t.Fatalf("76 checks at 6 in parallel = %s, want %s", got, want)
	}
	if got, want := collectionBudget(1, options), 2*30*time.Second; got != want {
		t.Fatalf("one check = %s, want %s", got, want)
	}
	// No budget stated is no bound, the same as everywhere else.
	if got := collectionBudget(76, model.RunOptions{}); got != 0 {
		t.Fatalf("an unset timeout should leave the call to the context, got %s", got)
	}
}
