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
	"karma/internal/model"
	"karma/internal/script"
)

func bodyText(inv model.Invocation) string {
	switch v := inv.(type) {
	case model.Command:
		return script.Join(v.Argv)
	case model.Shell:
		return v.Script
	case model.Dual:
		return v.Script
	}
	// An invocation with no shell rendering never reaches this point: the
	// local channel runs a Dual in process, and every other kind carries text.
	return ""
}

// posixShell: the login shell may not be POSIX, so both remote and shell-based local calls wrap another sh layer.
func posixShell(scriptText string) []string { return []string{"/bin/sh", "-c", scriptText} }

// RenderShell is a command string executable remotely: always through /bin/sh -c, with all arguments escaped.
func RenderShell(inv model.Invocation) string {
	return script.Join(posixShell(bodyText(inv)))
}

// ArgvFor is the argv for local exec. Command goes through exec without a shell; Shell goes through /bin/sh -c.
func ArgvFor(inv model.Invocation) []string {
	switch v := inv.(type) {
	case model.Command:
		return v.Argv
	default:
		return posixShell(bodyText(inv))
	}
}
