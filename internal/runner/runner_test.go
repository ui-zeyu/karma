package runner

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"karma/internal/model"
)

type deadObserver struct{}

func (deadObserver) CheckStarted(*model.Check)                      { panic("progress line blew up") }
func (deadObserver) CheckFinished(*model.Check, *model.CheckResult) { panic("panel blew up") }

// stubSession counts runs; checks run concurrently, so the counter is guarded.
type stubSession struct {
	mu   sync.Mutex
	runs int
}

func (s *stubSession) Name() string { return "stub" }

func (s *stubSession) Run(context.Context, model.Invocation, time.Duration, int) model.RunResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs++
	return model.RunResult{ExitCode: 0, Stdout: "out\n"}
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
			Probes: []model.Probe{{Label: "a", Inv: model.NewCommand("true")}}},
		{ID: "b", Aspect: model.AspectSystem,
			Probes: []model.Probe{{Label: "b", Inv: model.NewCommand("true")}}},
	}
	facts := model.HostFacts{AvailableBins: map[string]bool{"true": true}}
	RunCatalog(context.Background(), sess, facts, checks, model.RunOptions{Concurrency: 2}, deadObserver{})
	if got := sess.runCount(); got != len(checks) {
		t.Fatalf("both checks should finish after an observer panic: ran %d/%d", got, len(checks))
	}
}

// scriptSession replays one canned result per Run call in order; a chain runs
// its tiers sequentially, so the order is deterministic. onRun fires on every
// Run, so a test can cancel the context exactly when the first tier runs.
type scriptSession struct {
	mu    sync.Mutex
	reply []model.RunResult
	seen  int
	onRun func()
}

func (s *scriptSession) Name() string { return "script" }
func (s *scriptSession) Close() error { return nil }

func (s *scriptSession) Run(context.Context, model.Invocation, time.Duration, int) model.RunResult {
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

// chain builds one check whose fallback chain has one probe per label.
func chain(labels ...string) *model.Check {
	probes := make([]model.Probe, len(labels))
	for i, label := range labels {
		probes[i] = model.Probe{Label: label, Inv: model.NewCommand("tool-" + label)}
	}
	return &model.Check{ID: "chain", Aspect: model.AspectSystem, Probes: probes}
}

// bins marks every label's tool present.
func bins(labels ...string) model.HostFacts {
	available := map[string]bool{}
	for _, label := range labels {
		available["tool-"+label] = true
	}
	return model.HostFacts{AvailableBins: available}
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
			reply:       []model.RunResult{{ExitCode: 0, Stdout: "rows\n"}},
			wantProbe:   "ss",
			wantOutcome: model.Collected,
			wantRaw:     "rows\n",
		},
		{
			name:        "127 falls to the next tier",
			check:       chain("ss", "netstat"),
			facts:       bins("ss", "netstat"),
			reply:       []model.RunResult{{ExitCode: 127, Stderr: "command not found"}, {ExitCode: 0, Stdout: "rows\n"}},
			wantProbe:   "netstat",
			wantOutcome: model.Collected,
			wantSkipped: []string{"ss"},
			wantRaw:     "rows\n",
		},
		{
			name:        "a non-zero exit with empty stdout falls to the next tier",
			check:       chain("ss", "proc"),
			facts:       bins("ss", "proc"),
			reply:       []model.RunResult{{ExitCode: 1, Stderr: "permission denied"}, {ExitCode: 0, Stdout: "rows\n"}},
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
			reply:       []model.RunResult{{ExitCode: 0, Stdout: "rows\n"}},
			wantProbe:   "proc",
			wantOutcome: model.Collected,
			wantSkipped: []string{"ss"},
			wantRaw:     "rows\n",
		},
		{
			name:        "a timeout keeps the partial output and does not move on",
			check:       chain("lsof", "proc"),
			facts:       bins("lsof", "proc"),
			reply:       []model.RunResult{{TimedOut: true, ExitCode: -1, Stdout: "partial\n"}},
			wantProbe:   "lsof",
			wantOutcome: model.Collected,
			wantNote:    "timeout (2s), partial output kept",
			wantRaw:     "partial\n",
		},
		{
			name:        "a cancel keeps the partial output and does not move on",
			check:       chain("lsof", "proc"),
			facts:       bins("lsof", "proc"),
			reply:       []model.RunResult{{Interrupted: true, ExitCode: -1, Stdout: "partial\n"}},
			wantProbe:   "lsof",
			wantOutcome: model.Collected,
			wantNote:    "interrupted, partial output kept",
			wantRaw:     "partial\n",
		},
		{
			name:        "a failing last tier puts the error text in the panel",
			check:       chain("ss"),
			facts:       bins("ss"),
			reply:       []model.RunResult{{ExitCode: 1, Stderr: "no such file\n"}},
			wantProbe:   "ss",
			wantOutcome: model.Collected,
			wantNote:    "exit code 1: no such file",
		},
		{
			name:        "a silent last tier stays silent",
			check:       chain("ss"),
			facts:       bins("ss"),
			reply:       []model.RunResult{{ExitCode: 1}},
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

func TestRunCheckStopsWalkingTheChainOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := &scriptSession{
		reply: []model.RunResult{
			{Interrupted: true, ExitCode: -1},
			{ExitCode: 0, Stdout: "late\n"},
		},
		onRun: cancel, // the interrupt lands while the first tier runs
	}
	check := chain("lsof", "proc")
	result := runCheck(ctx, sess, bins("lsof", "proc"), check, model.RunOptions{Timeout: time.Second})
	if sess.ranCount() != 1 {
		t.Fatalf("a cancelled run must not try the next tier: ran %d tiers", sess.ranCount())
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
	RunCatalog(ctx, sess, bins("a"), []*model.Check{check}, model.RunOptions{Concurrency: 2}, deadObserver{})
	if got := sess.ranCount(); got != 0 {
		t.Fatalf("a cancelled run must not execute checks: ran %d", got)
	}
}
