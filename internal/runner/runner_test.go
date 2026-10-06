package runner

import (
	"context"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"karma/internal/model"
)

// deadObserver panics in both callbacks: the presentation layer is the run's own
// code, and one broken panel must not end the report. It records what the runner
// reported as damaged, which is the other half of the contract — a lost panel is
// said out loud.
type deadObserver struct {
	mu      sync.Mutex
	damaged []string
}

func (o *deadObserver) CheckStarted(*model.Check) { panic("progress line blew up") }

func (o *deadObserver) CheckFinished(*model.Check, *model.CheckResult) { panic("panel blew up") }

func (o *deadObserver) Damaged(check *model.Check, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.damaged = append(o.damaged, check.ID+": "+err.Error())
}

func (o *deadObserver) reported() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.damaged)
}

// stubSession counts runs; checks run concurrently, so the counter is guarded.
type stubSession struct {
	mu   sync.Mutex
	runs int
}

func (s *stubSession) Name() string { return "stub" }

func (s *stubSession) Channel() model.Channel { return model.ChanLocal }

func (s *stubSession) Describe() string { return "stub" }

func (s *stubSession) Run(context.Context, model.Call) model.RunResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs++
	return model.RunResult{Verdict: model.VerdictAnswered, Stdout: "out\n"}
}

func (s *stubSession) Close() error { return nil }

func (s *stubSession) runCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runs
}

func TestObserverPanicDoesNotKillRun(t *testing.T) {
	sess := &stubSession{}
	checks := []*model.Check{
		{ID: "a", Aspect: model.AspectSystem,
			Steps: []model.Step{{{Label: "a", Inv: model.NewCommand("true")}}}},
		{ID: "b", Aspect: model.AspectSystem,
			Steps: []model.Step{{{Label: "b", Inv: model.NewCommand("true")}}}},
	}
	facts := model.HostFacts{AvailableBins: map[string]bool{"true": true}}
	observer := &deadObserver{}
	summary := RunCatalog(context.Background(), sess, facts, checks, model.RunOptions{Concurrency: 2}, observer)
	if got := sess.runCount(); got != len(checks) {
		t.Fatalf("both checks should finish after an observer panic: ran %d/%d", got, len(checks))
	}
	if summary.Results != len(checks) {
		t.Fatalf("a damaged presentation still produces results: %+v", summary)
	}
	if got := observer.reported(); len(got) != 2*len(checks) {
		t.Fatalf("every dropped callback should be reported, got %v", got)
	}
}

// lostSession turns lost on its first run, the way a connection dropped under
// the first check does: every further call would fail the same way.
type lostSession struct {
	stubSession
	lost atomic.Bool
}

func (s *lostSession) Run(ctx context.Context, call model.Call) model.RunResult {
	s.lost.Store(true)
	return s.stubSession.Run(ctx, call)
}

func (s *lostSession) Lost() bool { return s.lost.Load() }

func TestLostChannelStopsTheQueue(t *testing.T) {
	sess := &lostSession{}
	checks := []*model.Check{
		{ID: "a", Aspect: model.AspectSystem,
			Steps: []model.Step{{{Label: "a", Inv: model.NewCommand("true")}}}},
		{ID: "b", Aspect: model.AspectSystem,
			Steps: []model.Step{{{Label: "b", Inv: model.NewCommand("true")}}}},
		{ID: "c", Aspect: model.AspectSystem,
			Steps: []model.Step{{{Label: "c", Inv: model.NewCommand("true")}}}},
	}
	facts := model.HostFacts{AvailableBins: map[string]bool{"true": true}}
	summary := RunCatalog(context.Background(), sess, facts, checks, model.RunOptions{Concurrency: 1}, &deadObserver{})
	if got := sess.runCount(); got != 1 {
		t.Fatalf("a channel lost under the first check should stop the queue: ran %d checks", got)
	}
	if !summary.LostChannel {
		t.Fatalf("the summary should say the transport died: %+v", summary)
	}
}

// scriptSession replays one canned result per Run call in order; a walk runs its
// steps sequentially, so the order is deterministic. onRun fires on every Run, so
// a test can cancel the context exactly when the first step runs.
type scriptSession struct {
	mu    sync.Mutex
	reply []model.RunResult
	seen  int
	onRun func()
}

func (s *scriptSession) Name() string { return "script" }

func (s *scriptSession) Channel() model.Channel { return model.ChanLocal }

func (s *scriptSession) Describe() string { return "script" }

func (s *scriptSession) Close() error { return nil }

func (s *scriptSession) Run(context.Context, model.Call) model.RunResult {
	s.mu.Lock()
	index := s.seen
	if index < len(s.reply) {
		s.seen++
	} else {
		index = -1
	}
	onRun := s.onRun
	s.mu.Unlock()
	if onRun != nil {
		onRun()
	}
	if index < 0 {
		return model.RunResult{}
	}
	return s.reply[index]
}

func (s *scriptSession) ranCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen
}

// chain builds one check whose walk has one single-probe step per label.
func chain(labels ...string) *model.Check {
	steps := make([]model.Step, len(labels))
	for i, label := range labels {
		steps[i] = model.Step{{Label: label, Inv: model.NewCommand("tool-" + label)}}
	}
	return &model.Check{ID: "chain", Aspect: model.AspectSystem, Steps: steps}
}

// bins marks every label's tool present.
func bins(labels ...string) model.HostFacts {
	available := map[string]bool{}
	for _, label := range labels {
		available["tool-"+label] = true
	}
	return model.HostFacts{AvailableBins: available}
}

// deadlineSession records the deadline the runner stated in the context, which
// is how one number reaches the channel and every step of the walk.
type deadlineSession struct {
	stubSession
	seen chan time.Time
}

func (s *deadlineSession) Run(ctx context.Context, call model.Call) model.RunResult {
	if deadline, ok := ctx.Deadline(); ok {
		s.seen <- deadline
	}
	return s.stubSession.Run(ctx, call)
}

// The budget belongs to the walk, and it travels in the context: the channel
// cannot start the clock late, so its own setup and every step of the check
// answer to the one number the operator gave.
func TestRunCheckStatesTheBudgetInTheContext(t *testing.T) {
	sess := &deadlineSession{seen: make(chan time.Time, 1)}
	budget := 30 * time.Second
	runCheck(context.Background(), sess, bins("ss"), chain("ss"), model.RunOptions{Timeout: budget})
	select {
	case deadline := <-sess.seen:
		if remaining := time.Until(deadline); remaining <= budget-time.Second || remaining > budget {
			t.Fatalf("the context should carry the check's budget, got %s left of %s", remaining, budget)
		}
	case <-time.After(time.Second):
		t.Fatal("the channel never saw a deadline: the budget would only be offered, not enforced")
	}
}

func TestRunCheckFallbackChain(t *testing.T) {
	options := model.RunOptions{Timeout: 2 * time.Second}
	cases := []struct {
		name        string
		check       *model.Check
		facts       model.HostFacts
		reply       []model.RunResult
		wantProbe   string
		wantOutcome model.Outcome
		wantSkipped []string
		wantNote    string
		wantRaw     string
	}{
		{
			name:        "first tier answers",
			check:       chain("ss", "netstat"),
			facts:       bins("ss", "netstat"),
			reply:       []model.RunResult{{Verdict: model.VerdictAnswered, Stdout: "rows\n"}},
			wantProbe:   "ss",
			wantOutcome: model.Collected,
			wantRaw:     "rows\n",
		},
		{
			name:        "127 falls to the next tier",
			check:       chain("ss", "netstat"),
			facts:       bins("ss", "netstat"),
			reply:       []model.RunResult{{Verdict: model.VerdictUnavailable, Stderr: "command not found", ExitCode: 127}, {Verdict: model.VerdictAnswered, Stdout: "rows\n"}},
			wantProbe:   "netstat",
			wantOutcome: model.Collected,
			wantSkipped: []string{"ss"},
			wantRaw:     "rows\n",
		},
		{
			name:        "a non-zero exit with empty stdout falls to the next tier",
			check:       chain("ss", "proc"),
			facts:       bins("ss", "proc"),
			reply:       []model.RunResult{{Verdict: model.VerdictFailed, Stderr: "permission denied", ExitCode: 1}, {Verdict: model.VerdictAnswered, Stdout: "rows\n"}},
			wantProbe:   "proc",
			wantOutcome: model.Collected,
			wantSkipped: []string{"ss"},
			wantRaw:     "rows\n",
		},
		{
			name:        "every tier lacks its binaries: skipped, nothing runs",
			check:       chain("ss", "netstat"),
			facts:       model.HostFacts{AvailableBins: map[string]bool{}},
			reply:       nil,
			wantProbe:   "",
			wantOutcome: model.Skipped,
			wantSkipped: []string{"ss", "netstat"},
		},
		{
			name:        "a missing first tier falls to the second",
			check:       chain("ss", "proc"),
			facts:       bins("proc"),
			reply:       []model.RunResult{{Verdict: model.VerdictAnswered, Stdout: "rows\n"}},
			wantProbe:   "proc",
			wantOutcome: model.Collected,
			wantSkipped: []string{"ss"},
			wantRaw:     "rows\n",
		},
		{
			name:        "a timeout keeps the partial output and does not move on",
			check:       chain("lsof", "proc"),
			facts:       bins("lsof", "proc"),
			reply:       []model.RunResult{{Verdict: model.VerdictTimedOut, ExitCode: -1, Stdout: "partial\n"}},
			wantProbe:   "lsof",
			wantOutcome: model.Collected,
			wantNote:    "timeout (2s), partial output kept",
			wantRaw:     "partial\n",
		},
		{
			// A tier the boundary abandoned (a body stuck in a syscall) kept
			// nothing, and the note must not promise output that is not there.
			name:        "a timeout with nothing read claims nothing",
			check:       chain("lsof", "proc"),
			facts:       bins("lsof", "proc"),
			reply:       []model.RunResult{{Verdict: model.VerdictTimedOut, ExitCode: -1}},
			wantProbe:   "lsof",
			wantOutcome: model.Collected,
			wantNote:    "timeout (2s)",
		},
		{
			name:        "a cancel keeps the partial output and does not move on",
			check:       chain("lsof", "proc"),
			facts:       bins("lsof", "proc"),
			reply:       []model.RunResult{{Verdict: model.VerdictInterrupted, ExitCode: -1, Stdout: "partial\n"}},
			wantProbe:   "lsof",
			wantOutcome: model.Collected,
			wantNote:    "interrupted, partial output kept",
			wantRaw:     "partial\n",
		},
		{
			name:        "a failing last tier puts the error text in the panel",
			check:       chain("ss"),
			facts:       bins("ss"),
			reply:       []model.RunResult{{Verdict: model.VerdictFailed, Stderr: "no such file\n", ExitCode: 1}},
			wantProbe:   "ss",
			wantOutcome: model.Collected,
			wantNote:    "exit code 1: no such file",
		},
		{
			name:        "a silent last tier stays silent",
			check:       chain("ss"),
			facts:       bins("ss"),
			reply:       []model.RunResult{{Verdict: model.VerdictFailed, ExitCode: 1}},
			wantProbe:   "",
			wantOutcome: model.Collected,
			wantSkipped: []string{"ss"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess := &scriptSession{reply: tc.reply}
			result := runCheck(context.Background(), sess, tc.facts, tc.check, options)
			if result.ProbeLabel != tc.wantProbe {
				t.Errorf("probe = %q, want %q", result.ProbeLabel, tc.wantProbe)
			}
			if result.Outcome != tc.wantOutcome {
				t.Errorf("outcome = %v, want %v", result.Outcome, tc.wantOutcome)
			}
			if !slices.Equal(result.SkippedLabels, tc.wantSkipped) {
				t.Errorf("skipped = %v, want %v", result.SkippedLabels, tc.wantSkipped)
			}
			if result.Note != tc.wantNote {
				t.Errorf("note = %q, want %q", result.Note, tc.wantNote)
			}
			if result.Raw != tc.wantRaw {
				t.Errorf("raw = %q, want %q", result.Raw, tc.wantRaw)
			}
		})
	}
}

func TestRunCheckStopsWalkingOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := &scriptSession{
		reply: []model.RunResult{
			{Verdict: model.VerdictInterrupted, ExitCode: -1},
			{Verdict: model.VerdictAnswered, Stdout: "late\n"},
		},
		onRun: cancel, // the interrupt lands while the first step runs
	}
	check := chain("lsof", "proc")
	result := runCheck(ctx, sess, bins("lsof", "proc"), check, model.RunOptions{Timeout: time.Second})
	if sess.ranCount() != 1 {
		t.Fatalf("a cancelled run must not try the next step: ran %d steps", sess.ranCount())
	}
	if result.Raw != "" {
		t.Fatalf("an interrupted tier with no output must not win: raw = %q", result.Raw)
	}
}

func TestRunCatalogStopsOnCancelledContext(t *testing.T) {
	sess := &scriptSession{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	check := chain("a")
	summary := RunCatalog(ctx, sess, bins("a"), []*model.Check{check}, model.RunOptions{Concurrency: 2}, &deadObserver{})
	if got := sess.ranCount(); got != 0 {
		t.Fatalf("a cancelled run must not execute checks: ran %d", got)
	}
	if !summary.Interrupted || summary.Results != 0 {
		t.Fatalf("the summary should say the run was interrupted: %+v", summary)
	}
}

// A tier with no branch for the session's channel is not part of that channel's
// chain: it neither runs nor appears among the skipped labels.
func TestRunCheckSkipsStepAbsentOnThisChannel(t *testing.T) {
	check := &model.Check{ID: "asym", Aspect: model.AspectProcess, Steps: []model.Step{
		{{Label: "walk", Inv: model.Dual{Script: "walk-script"}}}, // exists on ssh only
		{{Label: "next", Inv: model.NewCommand("tool-next")}},
	}}
	sess := &scriptSession{reply: []model.RunResult{{Verdict: model.VerdictAnswered, Stdout: "rows\n"}}}
	result := runCheck(context.Background(), sess, bins("next"), check, model.RunOptions{Timeout: time.Second})
	if result.ProbeLabel != "next" || result.Outcome != model.Collected {
		t.Fatalf("the channel-absent tier should be invisible: %+v", result)
	}
	if len(result.SkippedLabels) != 0 {
		t.Fatalf("a tier absent on this channel is not a skip: %v", result.SkippedLabels)
	}
	if sess.ranCount() != 1 {
		t.Fatalf("only the channel's tier should run: ran %d", sess.ranCount())
	}
}

// A step of several probes is one source's set of processes (one registry key
// each, where the channel has no shell to loop in): every member runs and the
// bodies join, instead of the walk stopping at the first member that happens to
// answer.
func TestRunCheckStepRunsEveryMember(t *testing.T) {
	check := &model.Check{ID: "regs", Aspect: model.AspectSystem, Steps: []model.Step{
		{{Label: "ps", Inv: model.NewCommand("powershell")}},
		{
			{Label: "run", Inv: model.NewCommand("tool-run")},
			{Label: "run-once", Inv: model.NewCommand("tool-run-once")},
			{Label: "services", Inv: model.NewCommand("tool-services")},
		},
	}}
	sess := &scriptSession{reply: []model.RunResult{
		{Verdict: model.VerdictAnswered, Stdout: "== run\nA\n"},
		{Verdict: model.VerdictAnswered, Stdout: "== run-once\nB\n"},
		// A member the target's registry does not carry: its stderr is not the
		// check's verdict while the step still has an answer.
		{Verdict: model.VerdictFailed, Stderr: "ERROR: not found\n", ExitCode: 1},
	}}
	// powershell absent: the plain step is skipped, and the set is entered.
	facts := bins("run", "run-once", "services")
	result := runCheck(context.Background(), sess, facts, check, model.RunOptions{Timeout: time.Second})
	if sess.ranCount() != 3 {
		t.Fatalf("every member of the step should run: ran %d", sess.ranCount())
	}
	if result.Outcome != model.Collected || result.ProbeLabel != "run + run-once + services" {
		t.Fatalf("the step should answer with every member named: %+v", result)
	}
	want := "== run\nA\n== run-once\nB\n"
	if result.Raw != want {
		t.Fatalf("raw = %q, want %q", result.Raw, want)
	}
	if result.Stderr != "" {
		t.Fatalf("a step that answered should not carry the failed member's stderr: %q", result.Stderr)
	}
	if len(result.SkippedLabels) != 1 || result.SkippedLabels[0] != "ps" {
		t.Fatalf("the skipped plain step should be reported: %v", result.SkippedLabels)
	}
}

// A body that lost its trailing newline does not glue onto the next member's
// first line: the joined body is what one tier would have printed.
func TestJoinStepSeparatesBodiesWithoutATrailingNewline(t *testing.T) {
	check := &model.Check{ID: "regs", Aspect: model.AspectSystem, Steps: []model.Step{{
		{Label: "a", Inv: model.NewCommand("tool-a")},
		{Label: "b", Inv: model.NewCommand("tool-b")},
	}}}
	sess := &scriptSession{reply: []model.RunResult{
		{Verdict: model.VerdictAnswered, Stdout: "last line of a"},
		{Verdict: model.VerdictAnswered, Stdout: "b\n"},
	}}
	result := runCheck(context.Background(), sess, bins("a", "b"), check, model.RunOptions{Timeout: time.Second})
	if result.Raw != "last line of a\nb\n" {
		t.Fatalf("raw = %q, want the two bodies on their own lines", result.Raw)
	}
}

// A step whose members all failed is the check's failure, carrying what they
// said: there is no answer to present.
func TestRunCheckStepWithNoAnswerIsAFailure(t *testing.T) {
	check := &model.Check{ID: "regs", Aspect: model.AspectSystem, Steps: []model.Step{{
		{Label: "a", Inv: model.NewCommand("tool-a")},
		{Label: "b", Inv: model.NewCommand("tool-b")},
	}}}
	sess := &scriptSession{reply: []model.RunResult{
		{Verdict: model.VerdictFailed, Stderr: "ERROR: a\n", ExitCode: 1},
		{Verdict: model.VerdictFailed, Stderr: "ERROR: b\n", ExitCode: 1},
	}}
	result := runCheck(context.Background(), sess, bins("a", "b"), check, model.RunOptions{Timeout: time.Second})
	if result.Outcome != model.Collected || !strings.Contains(result.Note, "exit code 1") {
		t.Fatalf("a step with no answer should report the failure: %+v", result)
	}
	if !strings.Contains(result.Stderr, "ERROR: a") || !strings.Contains(result.Stderr, "ERROR: b") {
		t.Fatalf("every member's stderr should reach the panel: %q", result.Stderr)
	}
}

// A step whose members all said the environment lacks them is unavailable, like
// any single tier: the walk moves on, and a walk of those is Skipped.
func TestRunCheckStepOfUnavailableMembersIsUnavailable(t *testing.T) {
	check := &model.Check{ID: "regs", Aspect: model.AspectSystem, Steps: []model.Step{{
		{Label: "a", Inv: model.NewCommand("tool-a")},
		{Label: "b", Inv: model.NewCommand("tool-b")},
	}}}
	sess := &scriptSession{reply: []model.RunResult{
		{Verdict: model.VerdictUnavailable, ExitCode: 127},
		{Verdict: model.VerdictUnavailable, ExitCode: 127},
	}}
	result := runCheck(context.Background(), sess, bins("a", "b"), check, model.RunOptions{Timeout: time.Second})
	if result.Outcome != model.Skipped {
		t.Fatalf("a step the environment lacks is a skip, not a failure: %+v", result)
	}
	if !slices.Equal(result.SkippedLabels, []string{"a + b"}) {
		t.Fatalf("the chain should name the step that was unavailable: %v", result.SkippedLabels)
	}
}

// A cut member ends the set: the members after it would read the same dead
// channel, and the partial output stays.
func TestRunCheckStepStopsAtACutMember(t *testing.T) {
	check := &model.Check{ID: "regs", Aspect: model.AspectSystem, Steps: []model.Step{{
		{Label: "a", Inv: model.NewCommand("tool-a")},
		{Label: "b", Inv: model.NewCommand("tool-b")},
	}}}
	sess := &scriptSession{reply: []model.RunResult{
		{Verdict: model.VerdictInterrupted, Stdout: "half\n", ExitCode: -1},
		{Verdict: model.VerdictAnswered, Stdout: "late\n"},
	}}
	result := runCheck(context.Background(), sess, bins("a", "b"), check, model.RunOptions{Timeout: time.Second})
	if sess.ranCount() != 1 {
		t.Fatalf("a cut member should end the set: ran %d", sess.ranCount())
	}
	if result.Raw != "half\n" || !strings.Contains(result.Note, "interrupted") {
		t.Fatalf("the cut member's output and note should be kept: %+v", result)
	}
}

// A shape cap is the row set the tier asked for: reaching it is the tier's own
// answer, not a cut. A scan cap bounds an open walk and is reported as cut.
func TestRunCheckMarksOnlyAScanCapsCut(t *testing.T) {
	shape := chain("top")
	shape.Steps[0][0].Cap = model.Shape(25)
	scan := chain("find")
	scan.Steps[0][0].Cap = model.Scan(200)
	for _, tc := range []struct {
		name  string
		check *model.Check
		want  bool
	}{
		{"a shape cap", shape, false},
		{"a scan cap", scan, true},
	} {
		sess := &scriptSession{reply: []model.RunResult{{Verdict: model.VerdictAnswered, Stdout: "rows\n", Truncated: true}}}
		result := runCheck(context.Background(), sess, bins("top", "find"), tc.check, model.RunOptions{Timeout: time.Second})
		if result.Document.Truncated != tc.want {
			t.Errorf("%s: truncated = %v, want %v", tc.name, result.Document.Truncated, tc.want)
		}
	}
}

// A panic inside a check's walk fails that check alone: the run keeps going and
// the panel names what broke, where an escaping panic would end the process and
// take the whole report with it.
func TestRunCheckSurvivesAPanickingSession(t *testing.T) {
	sess := &panickingSession{}
	checks := []*model.Check{
		{ID: "boom", Aspect: model.AspectSystem, Steps: []model.Step{{{Label: "x", Inv: model.NewCommand("boom")}}}},
		{ID: "fine", Aspect: model.AspectSystem, Steps: []model.Step{{{Label: "y", Inv: model.NewCommand("true")}}}},
	}
	facts := model.HostFacts{AvailableBins: map[string]bool{"boom": true, "true": true}}
	results := &collectObserver{}
	summary := RunCatalog(context.Background(), sess, facts, checks, model.RunOptions{Concurrency: 1}, results)
	if summary.Results != 2 {
		t.Fatalf("both checks should produce a result: %+v", summary)
	}
	damaged, ok := results.byID("boom")
	if !ok || damaged.Outcome != model.Failed || !strings.Contains(damaged.Note, "check boom") {
		t.Fatalf("the broken check should fail alone, naming the boundary: %+v", damaged)
	}
	if healthy, ok := results.byID("fine"); !ok || healthy.Outcome != model.Collected {
		t.Fatalf("the other check should be untouched: %+v", healthy)
	}
}

// panickingSession panics on one check's walk, the way a channel defect inside it
// would.
type panickingSession struct{ stubSession }

func (s *panickingSession) Run(ctx context.Context, call model.Call) model.RunResult {
	if cmd, ok := call.Inv.(model.Command); ok && cmd.Argv[0] == "boom" {
		panic("channel blew up")
	}
	return s.stubSession.Run(ctx, call)
}

// collectObserver keeps every result, for the tests that inspect them after the
// run has joined.
type collectObserver struct {
	mu      sync.Mutex
	results map[string]*model.CheckResult
}

func (o *collectObserver) CheckStarted(*model.Check) {}

func (o *collectObserver) CheckFinished(check *model.Check, result *model.CheckResult) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.results == nil {
		o.results = map[string]*model.CheckResult{}
	}
	o.results[check.ID] = result
}

func (o *collectObserver) Damaged(*model.Check, error) {}

func (o *collectObserver) byID(id string) (*model.CheckResult, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	result, ok := o.results[id]
	return result, ok
}
