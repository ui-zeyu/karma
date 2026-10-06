// Process exit codes: what the status says about the run, so a caller can tell
// an interruption from a channel that died and from karma's own damage without
// reading the message.

package cli

// ExitCode is the process status Main returns.
type ExitCode int

const (
	// ExitOK is a run that ended. A usage mistake the message explained is not a
	// failed run, so it leaves the status here too.
	ExitOK ExitCode = 0
	// ExitRead is a built-in reader that could not read an operand: the file it
	// was given is gone or unreadable, and the operands that did read have
	// already printed. It is the status a failed read carries, so a script that
	// checks $? sees it.
	ExitRead ExitCode = 1
	// ExitEnvironment is the environment failing the run: a connection that could
	// not be made, or a channel that died mid-run.
	ExitEnvironment ExitCode = 2
	// ExitInternal is karma's own damage: an internal error ended the run, so the
	// report is incomplete. It is sysexits' EX_SOFTWARE, kept distinct from the
	// environment's code so a script can tell the tool's defect from the target's.
	ExitInternal ExitCode = 70
	// ExitInterrupted is SIGINT or SIGTERM: the run stopped early and the report
	// holds what was collected.
	ExitInterrupted ExitCode = 130
)
