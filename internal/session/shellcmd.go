// shellcmd renders an Invocation into a shell command string and local argv.
//
// Remote rendering always wraps a /bin/sh -c layer: SSH exec interprets the
// command with the target user's login shell, which may be a non-POSIX shell
// such as fish/csh; the extra layer keeps syntax consistent. Local and remote
// share this rendering so both behave the same. The collecting identity is the
// login user. Word quoting lives in internal/script (sharing one escaping
// implementation with the collection scripts).

package session

import (
	"fmt"

	"karma/internal/model"
	"karma/internal/script"
)

// shellText is the invocation's shell text. ok is false for an invocation that
// has none: a Native body runs inside karma's process, which no channel from
// outside can reach — see noShellFor.
func shellText(inv model.Invocation) (string, bool) {
	switch v := inv.(type) {
	case model.Command:
		return script.Join(v.Argv), true
	case model.Shell:
		return v.Script, true
	}
	return "", false
}

// mustShellText is shellText for the call sites the catalog guarantees, where a
// tier that reaches a shell always declares the text for it. A missing one is a
// programming error, and it stops where it happens rather than running an empty
// script: an empty script exits 0 with no output, which reads as an answered
// tier.
func mustShellText(inv model.Invocation) string {
	text, ok := shellText(inv)
	if !ok {
		panic(fmt.Sprintf("no shell rendering for %T", inv))
	}
	return text
}

// posixShell: the login shell may not be POSIX, so both remote and shell-based local calls wrap another sh layer.
func posixShell(scriptText string) []string { return []string{"/bin/sh", "-c", scriptText} }

// noShellFor is the result a remote channel gives a call it cannot render: a
// Native body performs its tier inside karma's process, which is on the wrong
// side of the wire for a channel that reaches the target from outside.
// Unavailable — the 127 a missing binary gives — so the chain falls to the next
// tier, which may be a command the target can run itself.
func noShellFor(inv model.Invocation) model.RunResult {
	return model.RunResult{
		Verdict:  model.VerdictUnavailable,
		Stderr:   fmt.Sprintf("a %T tier runs only where karma itself runs", inv),
		ExitCode: 127,
	}
}

// RenderShell is a command string executable remotely: always through /bin/sh -c, with all arguments escaped.
func RenderShell(inv model.Invocation) string {
	return renderText(mustShellText(inv))
}

// renderText is RenderShell for a command string that is already built.
func renderText(scriptText string) string { return script.Join(posixShell(scriptText)) }

// ArgvFor is the argv for local exec. Command goes through exec without a shell; Shell goes through /bin/sh -c.
func ArgvFor(inv model.Invocation) []string {
	if cmd, ok := inv.(model.Command); ok {
		return cmd.Argv
	}
	return posixShell(mustShellText(inv))
}
