package runner

import (
	"testing"
	"time"

	"karma/internal/model"
)

type deadObserver struct{}

func (deadObserver) CheckStarted(*model.Check)                      { panic("progress line blew up") }
func (deadObserver) CheckFinished(*model.Check, *model.CheckResult) { panic("panel blew up") }

type stubSession struct{ runs int }

func (s *stubSession) Name() string   { return "stub" }
func (s *stubSession) Target() string { return "stub" }
func (s *stubSession) Run(model.Invocation, time.Duration, int) model.RunResult {
	s.runs++
	return model.RunResult{ExitCode: 0, Stdout: "out\n"}
}
func (s *stubSession) Close() error { return nil }

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
	if sess.runs != len(checks) {
		t.Fatalf("both checks should finish after an observer panic: ran %d/%d", sess.runs, len(checks))
	}
}
