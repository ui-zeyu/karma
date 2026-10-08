// A run: the channel it reads through, what one call answers, the row cap a tier
// declares, and the options the run was given.

package model

import "time"

// Outcome is how a check's walk ended. A tier that failed mid-walk is still
// Collected — its error text is the note the panel shows — so the other two
// values are the ones that say the walk did not run.
type Outcome int

const (
	// Collected: the walk ran. A tier that answered with an empty body and one
	// whose failure left only stderr are both this; the note carries which.
	Collected Outcome = iota
	// Skipped: every tier was unavailable here — the target's environment lacks
	// the command.
	Skipped
	// Failed: karma's own boundary broke this check, so the walk produced
	// nothing at all.
	Failed
)

// outcomeNames is the name of each Outcome in declaration order; the result
// stream writes one of them, so a result that crossed a process boundary says
// how its walk ended in one vocabulary.
var outcomeNames = []string{"collected", "skipped", "failed"}

// String names the outcome.
func (o Outcome) String() string {
	if o < 0 || int(o) >= len(outcomeNames) {
		return "unknown"
	}
	return outcomeNames[o]
}

// RunResult is the result of one call.
type RunResult struct {
	Verdict Verdict
	Stdout  string
	// Records is what a Fields tier read, the counterpart of Stdout: a call
	// answers with one of the two, and the reading layer takes whichever came.
	Records *RecordSet
	Stderr  string
	// ExitCode is the process's status; -1 when the call has none (a cut call,
	// or a channel that could not say).
	ExitCode int
	// Truncated marks a body a cap stopped: the source did not finish on its
	// own. Whether the panel reports that is the tier's row cap's decision.
	Truncated bool
}

// RowCap is a tier's row cap: how many rows the tier wants, and what reaching
// the cap means. The zero value is no cap.
type RowCap struct {
	// Rows is the row count the cap allows; 0 is no cap.
	Rows int
	// Answer marks a cap that is the tier's own answer: a sorted view's top N is
	// complete at the cap, so the panel is not told the body was cut. A scan cap
	// bounds an open walk and is presented as a cut.
	Answer bool
}

// Shape is the cap of a tier whose answer is a fixed number of rows: a listing
// head, or a sorted view's top N.
func Shape(rows int) RowCap { return RowCap{Rows: rows, Answer: true} }

// Scan is the cap that bounds an open scan, like `find ... | head`: reaching it
// is a cut, and the panel reports the body as truncated.
func Scan(rows int) RowCap { return RowCap{Rows: rows} }

// Cut reports whether a body this cap stopped is presented as cut. The byte
// safety valve's cut is a cut either way; this is only about the tier's own cap.
func (c RowCap) Cut() bool { return c.Rows > 0 && !c.Answer }

// HostFacts are the target's basic facts, collected in one opening round trip.
type HostFacts struct {
	Hostname string
	Kernel   string
	OsPretty string
	UID      int
	// Collection identity (USERDOMAIN\user on Windows; empty on Linux because
	// the report header already carries the uid)
	User string
	// ProbeCut marks the Windows capability probe — the two-step decision
	// between PowerShell and the registry — cut short by its deadline: a
	// PowerShell the probe did not reach reads as absent, so the fact layer
	// took the registry path and the run owes the operator that explanation.
	// No check's walk depends on it: a tier whose tool is missing says so
	// itself when it runs, and the chain falls through then. Linux states no
	// probe at all.
	ProbeCut bool
}

// IsRoot reports whether the uid is 0.
func (f HostFacts) IsRoot() bool { return f.UID == 0 }

// Channel is which side of the wire karma itself runs on. The session answers
// with the channel it is (ChanLocal, ChanSSH, ChanTTYD); the runner resolves
// each probe against that answer while walking the chain.
type Channel int8

const (
	// ChanLocal: karma itself runs on the collected host.
	ChanLocal Channel = iota + 1
	// ChanSSH: the target is reached over ssh.
	ChanSSH
	// ChanTTYD: the target is reached through a ttyd web terminal's websocket.
	ChanTTYD
)

// Remote reports whether the channel reaches the target from outside: the
// local channel is the one where karma itself stands on the collected host.
func (c Channel) Remote() bool { return c != ChanLocal }

// Source is which side of the wire this channel reads the evidence from: karma
// runs its own bodies only where karma itself runs, so a remote channel reads
// the target's own shell. The two are one decision, not two: a run states no
// source of its own.
func (c Channel) Source() Source {
	if c.Remote() {
		return SourceSh
	}
	return SourceNative
}

// Call is one call to run on the target: what to run, and how much of the
// output this tier wants. The deadline is not here because it is not a
// property of one call: it travels in the context, established by the caller
// that owns the policy — the runner gives one check's whole walk a single
// deadline (session.Within) — so every layer of the call answers to the same
// one, and the channel's own setup is covered by it too.
type Call struct {
	Inv Invocation
	Cap RowCap
}

// Run defaults, shared by the CLI options and RunOptions.
const (
	DefaultConcurrency = 6
	DefaultTimeout     = 30 * time.Second
	DefaultMaxLines    = 400
)

// RunOptions holds the run options shared by local and ssh.
type RunOptions struct {
	Selectors   []string
	Concurrency int
	Timeout     time.Duration
	MaxLines    int
	// MinSeverity is how much of the reading each check keeps: rows below the
	// floor are counted like filtered lines and left out of its document, so a
	// triage run can drop everything under one level. It filters what is shown
	// and nothing else: the collection's raw text is what the reading reads.
	MinSeverity SeverityFloor
	// JSON emits the run as the result stream — one JSON object per check,
	// written when that check finishes — instead of drawing the report. The
	// objects carry the tiers' raw text and how each walk ended; the reading,
	// the rules and the presentation stay with whoever reads the stream, so this
	// side applies MinSeverity and MaxLines to nothing.
	JSON bool
}
