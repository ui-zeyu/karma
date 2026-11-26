package watch

import (
	"strings"
	"testing"
	"time"

	"karma/internal/audit"
)

func TestLineSeparatesTheSourceFromTheJudgment(t *testing.T) {
	line := Line(Event{
		Source: SourcePoll,
		Proc:   &Proc{Kind: KindExec, PID: 42, PPID: 1, UID: 0, Comm: "dropper"},
		Verdict: &Verdict{
			Origin: audit.Runtime, Reach: audit.RootAsset, Severity: audit.Critical,
		},
	})
	for _, want := range []string{
		"source=poll", "origin=runtime", "reach=root", "severity=critical",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("line %q does not carry %q", line, want)
		}
	}
	if got := Line(Event{Source: SourcePoll, Proc: &Proc{Kind: KindExit, PID: 42}}); strings.Contains(got, "origin=") {
		t.Errorf("an exit carries no audit judgment: %q", got)
	}
}

func TestLineRendersBothBodies(t *testing.T) {
	proc := Line(Event{Time: time.Unix(1_700_000_000, 0), Source: SourcePoll, Proc: &Proc{
		Kind: KindExec, PID: 7, PPID: 1, UID: 0, Comm: "nginx", Exe: "/usr/sbin/nginx",
	}})
	for _, want := range []string{"exec", "pid=7", "ppid=1", "uid=0", "comm=nginx", "exe=/usr/sbin/nginx"} {
		if !strings.Contains(proc, want) {
			t.Errorf("proc line %q misses %q", proc, want)
		}
	}
	sock := Line(Event{Time: time.Unix(1_700_000_000, 0), Source: SourcePoll, Sock: &Sock{Net: NetEvent{
		Proto: "tcp", State: "ESTAB", Local: "10.0.0.2:49812", Peer: "198.51.100.25:443",
	}}})
	for _, want := range []string{"socket", "tcp", "ESTAB", "10.0.0.2:49812 -> 198.51.100.25:443", "pid=-"} {
		if !strings.Contains(sock, want) {
			t.Errorf("sock line %q misses %q", sock, want)
		}
	}
}
