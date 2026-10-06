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
// has none: a Native body runs inside karma's process, so a remote channel has
// nothing to render for it unless a collector on the target runs it — see
// commandText.
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

// commandText renders one remote call as a shell command: one probe of the
// collector placed on the target when there is one — that binary runs the tier
// in process and answers with the tier's own streams and status — and the
// invocation itself otherwise, the way every remote channel has always run it.
//
// Only a call that names a catalog tier can be delegated: the fact layer's own
// probes and the placement's small commands carry no check and no probe, and for
// them the invocation is the whole command.
func commandText(collector string, call model.Call) (string, bool) {
	if collector != "" && call.Check != "" && call.Probe != "" {
		return script.Join([]string{collector, "local", "probe", call.Check, call.Probe}), true
	}
	return shellText(call.Inv)
}

// noShellFor is the result a remote channel gives a call it cannot render: a
// Native body performs its tier inside karma's process, so a channel with no
// collector on the target has nothing to run for it. Unavailable — the 127 a
// missing binary gives — so the chain falls to the next tier, which may be a
// command the target can run itself.
func noShellFor(inv model.Invocation) model.RunResult {
	return model.RunResult{
		Verdict:  model.VerdictUnavailable,
		Stderr:   fmt.Sprintf("no collector on the target runs a %T tier", inv),
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
