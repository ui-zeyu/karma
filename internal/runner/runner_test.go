package runner

import (
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

func (s *stubSession) Run(model.Invocation, time.Duration, int) model.RunResult {
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
	RunCatalog(sess, facts, checks, model.RunOptions{Concurrency: 2}, deadObserver{})
	if got := sess.runCount(); got != len(checks) {
		t.Fatalf("both checks should finish after an observer panic: ran %d/%d", got, len(checks))
	}
}
