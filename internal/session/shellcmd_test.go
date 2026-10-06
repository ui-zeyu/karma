package session

import (
	"context"
	"slices"
	"testing"

	"karma/internal/model"
)

// A Command runs through exec as its own argv, untouched.
func TestArgvForCommand(t *testing.T) {
	got := ArgvFor(model.NewCommand("ps", "auxwwf"))
	if want := []string{"ps", "auxwwf"}; !slices.Equal(got, want) {
		t.Fatalf("argv = %v, want %v", got, want)
	}
}

// A Shell goes through /bin/sh -c locally too: the login shell may not be POSIX,
// and local and remote must behave the same.
func TestArgvForShell(t *testing.T) {
	got := ArgvFor(model.Shell{Script: "cat /etc/shadow"})
	if want := []string{"/bin/sh", "-c", "cat /etc/shadow"}; !slices.Equal(got, want) {
		t.Fatalf("argv = %v, want %v", got, want)
	}
}

// The rendered command string is what the SSH channel sends: every argument quoted
// for the login shell.
func TestRenderShell(t *testing.T) {
	if got, want := RenderShell(model.NewCommand("uname", "-r")), `/bin/sh -c 'uname -r'`; got != want {
		t.Fatalf("render = %q, want %q", got, want)
	}
	if got, want := RenderShell(model.Shell{Script: `cat /etc/os-release; echo done`}),
		`/bin/sh -c 'cat /etc/os-release; echo done'`; got != want {
		t.Fatalf("render = %q, want %q", got, want)
	}
}

// A call on a channel that collected through a placed collector is one probe of
// that binary: the tier runs on the target, in process, and answers with its own
// streams and status.
func TestCommandTextAsksTheCollectorForOneProbe(t *testing.T) {
	call := model.Call{
		Check: "listen",
		Probe: "ss",
		Inv:   model.Dual{Run: func(context.Context) (string, error) { return "x", nil }, Script: "ss -tunap"},
	}
	got := commandText("/root/.karma/karma", call)
	if want := "/root/.karma/karma local probe listen ss"; got != want {
		t.Fatalf("commandText = %q, want %q", got, want)
	}
	// Without a collector the invocation is what runs, the way it always has.
	if got := commandText("", call); got != "ss -tunap" {
		t.Fatalf("commandText without a collector = %q", got)
	}
}

// delegateSession is a remote channel carrying a placed collector.
type delegateSession struct {
	collector string
}

func (s *delegateSession) Name() string           { return "ssh" }
func (s *delegateSession) Channel() model.Channel { return model.ChanSSH }
func (s *delegateSession) Describe() string       { return "ssh" }
func (s *delegateSession) Close() error           { return nil }

func (s *delegateSession) Run(context.Context, model.Call) model.RunResult {
	return model.RunResult{Verdict: model.VerdictAnswered}
}

func (s *delegateSession) UseCollector(path string) { s.collector = path }
func (s *delegateSession) Collector() string        { return s.collector }

// The tiers a delegated channel runs are the local ones: that binary stands on
// the target, so a tier without an in-process body does not exist there either.
// What the transport is — Channel — does not change.
func TestTierChannelFollowsTheCollector(t *testing.T) {
	sess := &delegateSession{}
	if got := TierChannel(sess); got != model.ChanSSH {
		t.Fatalf("a channel with no collector runs its own tiers: %v", got)
	}
	if got := sess.Channel(); got != model.ChanSSH {
		t.Fatalf("the transport stays the transport: %v", got)
	}
	sess.UseCollector("/root/.karma/karma")
	if got := TierChannel(sess); got != model.ChanLocal {
		t.Fatalf("a placed collector runs the local tiers: %v", got)
	}
}

// A call that names no catalog tier is not delegated: the fact layer's probes and
// the placement's own small commands run their invocation, collector or not.
func TestCommandTextLeavesUnnamedCallsAlone(t *testing.T) {
	call := model.Call{Inv: model.Shell{Script: "uname -r"}}
	if got := commandText("/root/.karma/karma", call); got != "uname -r" {
		t.Fatalf("commandText delegated a call with no tier: %q", got)
	}
	half := model.Call{Check: "listen", Inv: model.Shell{Script: "uname -r"}}
	if got := commandText("/root/.karma/karma", half); got != "uname -r" {
		t.Fatalf("commandText delegated a call with no probe: %q", got)
	}
}
