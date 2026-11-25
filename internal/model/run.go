// A run: the channel a call goes through, what the call answers, and how the
// channel says it ended.

package model

// Verdict is how one call ended, as the channel could tell.
type Verdict int8

const (
	// VerdictFailed: the call produced no answer — the channel broke, or the
	// command exited non-zero with nothing on stdout.
	VerdictFailed Verdict = iota
	// VerdictAnswered: stdout is the answer, the exit code and all.
	VerdictAnswered
	// VerdictUnavailable: the environment lacks the command (127).
	VerdictUnavailable
	// VerdictTimedOut: the deadline stopped the source; what arrived is kept.
	VerdictTimedOut
	// VerdictInterrupted: cancellation stopped the source; what arrived is kept.
	VerdictInterrupted
)

// Settled reports whether this call ended the walk.
func (v Verdict) Settled() bool {
	return v == VerdictAnswered || v == VerdictTimedOut || v == VerdictInterrupted
}

// Cut reports whether the call was stopped mid-flight.
func (v Verdict) Cut() bool { return v == VerdictTimedOut || v == VerdictInterrupted }

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

// RunResult is the result of one call.
type RunResult struct {
	Verdict   Verdict
	Stdout    string
	Stderr    string
	ExitCode  int
	Truncated bool
}

// RowCap bounds a body at a line count. A zero Rows is no cap.
type RowCap struct {
	Rows   int
	Answer bool
}

// Cut reports whether a body this cap stopped is a cut.
func (c RowCap) Cut() bool { return c.Rows > 0 && !c.Answer }

// Call is one script to run on the target and the row cap it asks for.
type Call struct {
	Inv Invocation
	Cap RowCap
}
