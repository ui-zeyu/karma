// Invocation: how a tier gets its text, which source walks it, and how its
// call ended.

package model

import (
	"context"
	"errors"
)

// Invocation is one way a tier gets its text: Command goes through exec
// without a shell, Shell is a script that must go through /bin/sh -c (globs,
// redirections, loops), Native is a body run inside karma's own process. The
// unexported method seals the implementation set, and each variant states for
// itself which source walks it (RunsOn), so a new kind of tier cannot inherit
// a source rule by landing in a switch's default branch.
type Invocation interface {
	isInvocation()
	// RunsOn reports whether a run in this source walks a tier of this kind.
	RunsOn(Source) bool
}

// Command is an argv call; the required binary is Argv's first word.
type Command struct{ Argv []string }

// NewCommand builds an argv call; an empty argv fails during catalog
// construction.
func NewCommand(argv ...string) Command {
	if len(argv) == 0 {
		panic("Command.argv must not be empty")
	}
	return Command{Argv: argv}
}

func (Command) isInvocation() {}

// RunsOn is true for either source: a command runs wherever the session points.
func (Command) RunsOn(Source) bool { return true }

// Shell is a script call: handed to /bin/sh -c, requires no binary.
type Shell struct{ Script string }

func (Shell) isInvocation() {}

// RunsOn is true for either source, like a command's.
func (Shell) RunsOn(Source) bool { return true }

// Native is a tier whose body is karma's own code: the local channel runs it
// inside the process, which is how a tier reads the kernel's interfaces without
// a host tool or a shell. A remote channel cannot run it — there is no karma on
// the target — so such a tier is walked by the native source alone, and a
// session asked for one answers the way it answers any absent tool.
//
// Whether the body can run here is its own answer at run time
// (ErrTierUnavailable), never a declaration read before the walk.
type Native struct {
	Body func(ctx context.Context) (string, error)
}

func (Native) isInvocation() {}

// RunsOn is the native source alone: the body runs in karma's own process.
func (Native) RunsOn(s Source) bool { return s == SourceNative }

// Fields is a tier whose body reads fields rather than a tool's own wording:
// the local channel runs it in process and the result is the records
// themselves, so nothing formats them into a line for another layer to parse
// back out. It is a Native in every other respect — the local channel answers
// with it, it reports ErrTierUnavailable the same way, and the walk ranks it
// like any other tier.
type Fields struct {
	Read func(ctx context.Context) (*RecordSet, error)
}

func (Fields) isInvocation() {}

// RunsOn is the native source alone, like a Native's.
func (Fields) RunsOn(s Source) bool { return s == SourceNative }

// Script is a tier of the sh source: a command whose pinned wording is the
// reading (LC_ALL=C, the exact flags), run wherever the session points — the
// target's own /bin/sh through the channel — and, when Parse is set, read back
// into the same records the native source states for the check. The parse is
// karma's own code, so the tool's layout freedom — column widths, alignment,
// the locale's month names — ends at the parser; text the parser does not
// recognize is the tier's failure, which declines rather than guesses.
//
// A nil Parse is a tier whose text is its body: the check's evidence is a file's
// contents, a listing or a walk rather than a table karma states field by field,
// and the reading layer reads those lines the way it reads any other body. Both
// kinds belong to the sh source alone, because the native source reads the same
// evidence with its own body: the two stand side by side, never in one another's
// fallback chain.
type Script struct {
	Run   string
	Parse func(stdout string) (*RecordSet, error)
}

// Sh builds the sh source's tier whose text is the body, from the pinned spelling.
func Sh(run string) Script { return Script{Run: run} }

func (Script) isInvocation() {}

// RunsOn is the sh source alone: the tier is that source's spelling of the
// evidence, read over the target's own shell.
func (Script) RunsOn(s Source) bool { return s == SourceSh }

// Source is which side of the wire reads the evidence, and the run's own
// channel states it (Channel.Source). The native source is where karma itself
// stands: its own bodies run in process. The sh source reads a target through
// that target's shell — the run drives /bin/sh over the channel and reads each
// check's pinned spelling into the same layer-1 structure. A run walks only its
// own source's tiers (each invocation kind answers for itself whether this
// source walks it); the two never chain, because a report stands on one source
// and each source keeps its own escape ladder.
type Source string

const (
	SourceNative Source = "" // unset is the native source
	SourceSh     Source = "sh"
)

// ErrTierUnavailable marks a Native body that cannot run in this environment
// (wrong platform, no /proc): the session reports it like a missing binary
// (exit 127) so the probe chain falls to the next tier.
var ErrTierUnavailable = errors.New("native tier unavailable in this environment")

// Verdict is how one call ended, as the channel could tell. It is what the
// fallback chain reads: a tier that settled the question ends the walk (an
// answer, or a cut whose partial output is kept), and an unavailable or failed
// tier leaves the walk going. The channel boundary states it, so no caller has
// to know the exit codes' conventions.
type Verdict int8

const (
	// VerdictFailed: the call produced no answer — the channel broke, or the
	// command exited non-zero with nothing on stdout. Stderr is what a panel
	// then names.
	VerdictFailed Verdict = iota
	// VerdictAnswered: stdout is this tier's answer, the exit code and all. An
	// empty stdout is an answer too (a verifier with nothing to report).
	VerdictAnswered
	// VerdictUnavailable: the environment lacks this tier — a binary the shell's
	// own guard reported missing (127), or an in-process body that cannot run
	// here. The chain falls to the next tier.
	VerdictUnavailable
	// VerdictTimedOut: the deadline stopped the source. The output already
	// produced is kept and the chain does not advance.
	VerdictTimedOut
	// VerdictInterrupted: cancellation (Ctrl-C) stopped the source, which keeps
	// the output it had produced. The chain does not advance.
	VerdictInterrupted
)

// Settled reports whether this tier ended the walk: it answered, or it was cut
// short and its partial output is what stays. A failed or unavailable tier
// leaves the chain walking.
func (v Verdict) Settled() bool {
	return v == VerdictAnswered || v == VerdictTimedOut || v == VerdictInterrupted
}

// Cut reports whether the call was stopped mid-flight by the deadline or by
// cancellation, with the output it had produced kept.
func (v Verdict) Cut() bool { return v == VerdictTimedOut || v == VerdictInterrupted }

// String names the verdict, for the messages that report a call that did not
// answer.
func (v Verdict) String() string {
	switch v {
	case VerdictAnswered:
		return "answered"
	case VerdictUnavailable:
		return "unavailable"
	case VerdictTimedOut:
		return "timed out"
	case VerdictInterrupted:
		return "interrupted"
	}
	return "failed"
}
