package session

import (
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
