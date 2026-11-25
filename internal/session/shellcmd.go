// shellcmd renders an Invocation into a shell command string and local argv.
//
// Remote rendering always wraps a /bin/sh -c layer: SSH exec interprets the
// command with the target user's login shell, which may be a non-POSIX shell
// such as fish/csh; the extra layer keeps syntax consistent. Local and remote
// share this rendering so both behave the same. Word quoting lives in
// internal/script.

package session

import (
	"fmt"

	"karma/internal/model"
	"karma/internal/script"
)

// shellText is the invocation's shell text. Shell is the only kind.
func shellText(inv model.Invocation) (string, bool) {
	if shell, ok := inv.(model.Shell); ok {
		return shell.Script, true
	}
	return "", false
}

// mustShellText is shellText for the call sites the audit guarantees.
func mustShellText(inv model.Invocation) string {
	text, ok := shellText(inv)
	if !ok {
		panic(fmt.Sprintf("no shell rendering for %T", inv))
	}
	return text
}

// posixShell: the login shell may not be POSIX, so both remote and shell-based local calls wrap another sh layer.
func posixShell(scriptText string) []string { return []string{"/bin/sh", "-c", scriptText} }

// noShellFor is the result a channel gives a call it cannot render.
func noShellFor(inv model.Invocation) model.RunResult {
	return model.RunResult{
		Verdict:  model.VerdictUnavailable,
		Stderr:   fmt.Sprintf("a %T tier runs only where karma itself runs", inv),
		ExitCode: 127,
	}
}

// RenderShell is a command string executable remotely: always through /bin/sh -c.
func RenderShell(inv model.Invocation) string { return renderText(mustShellText(inv)) }

// renderText is RenderShell for a string that is already built.
func renderText(scriptText string) string { return script.Join(posixShell(scriptText)) }

// ArgvFor is the argv for local exec.
func ArgvFor(inv model.Invocation) []string { return posixShell(mustShellText(inv)) }
