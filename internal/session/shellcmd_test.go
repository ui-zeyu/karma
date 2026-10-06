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
// streams and status — whatever the tier's invocation is, a body karma carries
// included.
func TestCommandTextAsksTheCollectorForOneProbe(t *testing.T) {
	call := model.Call{
		Check: "listen",
		Probe: "ss",
		Inv:   model.Native{Body: func(context.Context) (string, error) { return "x", nil }},
	}
	got, ok := commandText("/root/.karma/karma", call)
	if !ok {
		t.Fatal("a delegated tier has a command")
	}
	if want := "/root/.karma/karma local probe listen ss"; got != want {
		t.Fatalf("commandText = %q, want %q", got, want)
	}
	// Without a collector the invocation is what runs, the way it always has.
	if got, ok := commandText("", model.Call{Inv: model.NewCommand("ss", "-tunap")}); !ok || got != "ss -tunap" {
		t.Fatalf("commandText without a collector = %q, %v", got, ok)
	}
}

// A Native body has no shell text: with no collector on the target there is
// nothing for a remote channel to run, which is a call the channel answers
// unavailable rather than a command string.
func TestCommandTextHasNoTextForANativeWithoutACollector(t *testing.T) {
	call := model.Call{
		Check: "lsmod", Probe: "lsmod",
		Inv: model.Native{Body: func(context.Context) (string, error) { return "x", nil }},
	}
	if got, ok := commandText("", call); ok {
		t.Fatalf("a Native body has no shell rendering, got %q", got)
	}
	res := noShellFor(call.Inv)
	if res.Verdict != model.VerdictUnavailable || res.ExitCode != 127 {
		t.Fatalf("an unrenderable call reads as unavailable/127, got %+v", res)
	}
}

// A call that names no catalog tier is not delegated: the fact layer's probes and
// the placement's own small commands run their invocation, collector or not.
func TestCommandTextLeavesUnnamedCallsAlone(t *testing.T) {
	call := model.Call{Inv: model.Shell{Script: "uname -r"}}
	if got, ok := commandText("/root/.karma/karma", call); !ok || got != "uname -r" {
		t.Fatalf("commandText delegated a call with no tier: %q", got)
	}
	half := model.Call{Check: "listen", Inv: model.Shell{Script: "uname -r"}}
	if got, ok := commandText("/root/.karma/karma", half); !ok || got != "uname -r" {
		t.Fatalf("commandText delegated a call with no probe: %q", got)
	}
}
