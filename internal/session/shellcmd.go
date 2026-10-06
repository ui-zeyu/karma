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
// carries none: a Dual whose script side does not exist — the runner never
// routes one to a remote channel (model.Dual.For) — and any future Invocation
// kind that has not taught this renderer about itself.
func shellText(inv model.Invocation) (string, bool) {
	switch v := inv.(type) {
	case model.Command:
		return script.Join(v.Argv), true
	case model.Shell:
		return v.Script, true
	case model.Dual:
		return v.Script, v.Script != ""
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
func commandText(collector string, call model.Call) string {
	if collector == "" || call.Check == "" || call.Probe == "" {
		return mustShellText(call.Inv)
	}
	return script.Join([]string{collector, "local", "probe", call.Check, call.Probe})
}

// RenderShell is a command string executable remotely: always through /bin/sh -c, with all arguments escaped.
func RenderShell(inv model.Invocation) string {
	return script.Join(posixShell(mustShellText(inv)))
}

// ArgvFor is the argv for local exec. Command goes through exec without a shell; Shell goes through /bin/sh -c.
func ArgvFor(inv model.Invocation) []string {
	if cmd, ok := inv.(model.Command); ok {
		return cmd.Argv
	}
	return posixShell(mustShellText(inv))
}
