package watch

import (
	"strings"
	"testing"
)

func TestLineSeparatesTheSourceFromTheJudgment(t *testing.T) {
	line := Line(Event{
		Kind: KindExec, PID: 42, PPID: 1, UID: 0, Comm: "dropper",
		Source: "poll", Origin: "runtime", Reach: "root", Severity: "critical",
	})
	for _, want := range []string{
		"source=poll", "origin=runtime", "reach=root", "severity=critical",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("line %q does not carry %q", line, want)
		}
	}
	if got := Line(Event{Kind: KindExit, PID: 42, Source: "poll"}); strings.Contains(got, "origin=") {
		t.Errorf("an exit carries no audit judgment: %q", got)
	}
}
