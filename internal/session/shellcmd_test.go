package session

import (
	"context"
	"slices"
	"testing"

	"karma/internal/model"
)

// A Command runs through exec as its own argv, untouched.
func TestArgvForCommand(t *testing.T) {
	t.Parallel()
	got := ArgvFor(model.NewCommand("ps", "auxwwf"))
	if want := []string{"ps", "auxwwf"}; !slices.Equal(got, want) {
		t.Fatalf("argv = %v, want %v", got, want)
	}
}

// A Shell goes through /bin/sh -c locally too: the login shell may not be POSIX,
// and local and remote must behave the same.
func TestArgvForShell(t *testing.T) {
	t.Parallel()
	got := ArgvFor(model.Shell{Script: "cat /etc/shadow"})
	if want := []string{"/bin/sh", "-c", "cat /etc/shadow"}; !slices.Equal(got, want) {
		t.Fatalf("argv = %v, want %v", got, want)
	}
}

// The rendered command string is what the SSH channel sends: every argument quoted
// for the login shell.
func TestRenderShell(t *testing.T) {
	t.Parallel()
	if got, want := RenderShell(model.NewCommand("uname", "-r")), `/bin/sh -c 'uname -r'`; got != want {
		t.Fatalf("render = %q, want %q", got, want)
	}
	if got, want := RenderShell(model.Shell{Script: `cat /etc/os-release; echo done`}),
		`/bin/sh -c 'cat /etc/os-release; echo done'`; got != want {
		t.Fatalf("render = %q, want %q", got, want)
	}
}

// Every call is rendered from its own invocation: a tier's command is a plain
// command line, so nothing in the renderer has to know what a call is for.
func TestShellTextRendersEveryInvocationKind(t *testing.T) {
	t.Parallel()
	cases := []struct {
		inv  model.Invocation
		want string
	}{
		{model.NewCommand("uname", "-r"), "uname -r"},
		{model.Shell{Script: "cat /etc/os-release"}, "cat /etc/os-release"},
	}
	for _, tc := range cases {
		if got, ok := shellText(tc.inv); !ok || got != tc.want {
			t.Errorf("shellText(%T) = %q, %v; want %q", tc.inv, got, ok, tc.want)
		}
	}
}

// A Native body has no shell text: a remote channel has nothing to run for it —
// the body is karma's own code and karma is not on the target — so an
// unrenderable call is answered unavailable rather than with a command string.
func TestANativeBodyHasNoShellText(t *testing.T) {
	t.Parallel()
	call := model.Call{Inv: model.Native{Body: func(context.Context) (string, error) { return "x", nil }}}
	if got, ok := shellText(call.Inv); ok {
		t.Fatalf("a Native body has no shell rendering, got %q", got)
	}
	res := noShellFor(call.Inv)
	if res.Verdict != model.VerdictUnavailable || res.ExitCode != 127 {
		t.Fatalf("an unrenderable call reads as unavailable/127, got %+v", res)
	}
}
