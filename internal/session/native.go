// In-process tier glue: the local channel runs a Native tier's body inside
// karma itself. Result semantics mirror a subprocess tier: the call's deadline
// and cancellation keep the partial text, ErrTierUnavailable maps to the
// missing-binary 127 so the probe chain falls through, and the line and byte
// caps mirror harvest's.
//
// The deadline is enforced, not merely offered. A body parked in a syscall — a
// FIFO planted at a path it reads, a wedged mount, a blocked device read —
// never observes a cancelled context, and nothing else can stop it either: no
// signal breaks an open(2) wait, and Go cannot kill a goroutine. So the body
// runs on its own goroutine and the caller stops waiting at the deadline,
// keeping the run bounded for every in-process tier rather than for the read
// sites that were audited. A body that does respect the context gets a short
// grace to hand back what it read, which keeps the cooperative path's partial
// output.

package session

import (
	"context"
	"errors"
	"strings"
	"time"

	"karma/internal/fault"
	"karma/internal/model"
	"karma/internal/textutil"
)

// bodyGrace is how long a body that is already unwinding (every walk checks the
// context) has to hand back its partial answer before the caller abandons it.
const bodyGrace = 250 * time.Millisecond

// boundedCall runs one in-process body under the call's deadline. The body runs
// on its own goroutine behind the fault boundary, so one broken tier fails
// alone; the caller stops waiting when the deadline ends, because a body parked
// in a syscall — a FIFO planted at a path it reads, a wedged mount, a blocked
// device read — observes no context and no signal can end it: after bodyGrace
// the call is reported as the cut and the goroutine is left where it is, holding
// nothing the report needs. A body that does respect the context gets the grace
// to hand back the partial text it had already read.
func boundedCall(ctx context.Context, body func(context.Context) model.RunResult) model.RunResult {
	// Buffered: an abandoned body must never block on its own send.
	done := make(chan model.RunResult, 1)
	go func() {
		result, damage := fault.Result("in-process tier", func() model.RunResult { return body(ctx) })
		if damage != nil {
			result = model.RunResult{Verdict: model.VerdictFailed, Stderr: damage.Error(), ExitCode: 1}
		}
		done <- result
	}()
	select {
	case result := <-done:
		return result
	case <-ctx.Done():
		select {
		case result := <-done:
			return result
		case <-time.After(bodyGrace):
			return model.RunResult{Verdict: cutVerdict(ctx), ExitCode: -1}
		}
	}
}

func runNative(ctx context.Context, fn func(context.Context) (string, error), cap model.RowCap) model.RunResult {
	if fn == nil {
		// A Native with no body is a catalog mistake rather than a target's
		// answer; it reads as a tier that cannot run here, which the chain in
		// the runner falls through.
		return model.RunResult{Verdict: model.VerdictUnavailable, Stderr: model.ErrTierUnavailable.Error(), ExitCode: 127}
	}
	result := boundedCall(ctx, func(ctx context.Context) model.RunResult { return textResult(fn(ctx)) })
	if result.Verdict != model.VerdictAnswered {
		return result
	}
	text, truncated := capLines(result.Stdout, cap.Rows)
	if int64(len(text)) > maxHarvestBytes {
		text = text[:maxHarvestBytes]
		truncated = true
	}
	result.Stdout, result.Truncated = validText(text), truncated
	return result
}

// textResult is one finished text body's result: the endings a channel reads
// from its own processes, stated at the boundary where the body's context is
// the call's — a deadline or the operator's cancellation keeps the partial text
// the body had produced.
func textResult(text string, err error) model.RunResult {
	switch {
	case err == nil:
	case errors.Is(err, model.ErrTierUnavailable):
		return model.RunResult{Verdict: model.VerdictUnavailable, Stderr: err.Error(), ExitCode: 127}
	case errors.Is(err, context.DeadlineExceeded):
		return model.RunResult{Verdict: model.VerdictTimedOut, Stdout: validText(text), ExitCode: -1}
	case errors.Is(err, context.Canceled):
		return model.RunResult{Verdict: model.VerdictInterrupted, Stdout: validText(text), ExitCode: -1}
	default:
		return model.RunResult{Verdict: model.VerdictFailed, Stderr: err.Error(), ExitCode: 1}
	}
	return model.RunResult{Verdict: model.VerdictAnswered, Stdout: validText(text)}
}

// runFields runs a Fields tier's body: the same boundary as runNative (a panic
// fails one tier, the deadline abandons a body parked in a syscall), with the
// records themselves as the answer. The row cap applies to the records, so a
// capped body is capped before anything is rendered from it.
func runFields(ctx context.Context, read func(context.Context) (*model.RecordSet, error), cap model.RowCap) model.RunResult {
	if read == nil {
		return model.RunResult{Verdict: model.VerdictUnavailable, Stderr: model.ErrTierUnavailable.Error(), ExitCode: 127}
	}
	return finishFields(boundedCall(ctx, func(ctx context.Context) model.RunResult {
		set, err := read(ctx)
		if err != nil {
			return fieldFailure(err)
		}
		return model.RunResult{Verdict: model.VerdictAnswered, Records: set}
	}), cap)
}

// finishFields is the Fields tier's verdict mapping: the same endings as a text
// body (an unavailable interface falls through, a deadline keeps what was read),
// read from the same place.
func finishFields(result model.RunResult, cap model.RowCap) model.RunResult {
	if result.Records == nil {
		return result
	}
	if cap.Rows > 0 && len(result.Records.Rows) > cap.Rows {
		result.Records.Rows = result.Records.Rows[:cap.Rows]
		result.Truncated = true
	}
	if cap.Answer {
		result.Truncated = false
	}
	return result
}

// scriptRead is a parser's two answers, carried through one panic boundary.
type scriptRead struct {
	set *model.RecordSet
	err error
}

// fieldFailure reads a Fields body's own error the way textResult reads a text
// body's: an interface this host lacks leaves the tier unavailable —
// which is how a body that knows it cannot run here hands the walk on — while
// anything else is the tier's failure. A body that stopped at the deadline has
// no partial records to keep: its signature answers with a set or an error.
func fieldFailure(err error) model.RunResult {
	switch {
	case errors.Is(err, model.ErrTierUnavailable):
		return model.RunResult{Verdict: model.VerdictUnavailable, Stderr: err.Error(), ExitCode: 127}
	case errors.Is(err, context.DeadlineExceeded):
		return model.RunResult{Verdict: model.VerdictTimedOut, ExitCode: -1}
	case errors.Is(err, context.Canceled):
		return model.RunResult{Verdict: model.VerdictInterrupted, ExitCode: -1}
	default:
		return model.RunResult{Verdict: model.VerdictFailed, Stderr: err.Error(), ExitCode: 1}
	}
}

// runScript is a Script tier's front on every channel: the pinned command runs
// as the channel's own shell call, and what came back is read into the records
// the parser states. The two halves belong together — a channel that ran the
// shell text without the parse would answer a Script tier with the tool's own
// layout — so every channel states them here rather than at each of its Run
// methods.
func runScript(ctx context.Context, run func(context.Context, model.Call) model.RunResult,
	script model.Script, cap model.RowCap) model.RunResult {
	return finishScript(run(ctx, scriptCall(script, cap)), script, cap)
}

// scriptCall is the shell harvest of a Script tier. A parser turns that text
// into records, and a header line is not a record, so the row cap waits until
// the records exist; the harvest's byte valve still bounds the text. A tier
// with no parser is its own text, and the cap stays on the harvest.
func scriptCall(script model.Script, cap model.RowCap) model.Call {
	if script.Parse != nil {
		cap = model.RowCap{}
	}
	return model.Call{Inv: model.Shell{Script: script.Run}, Cap: cap}
}

// finishScript reads a Script tier's captured text as the records its parser
// states: the parse is the tier's body, with the same endings a Fields body
// reports. A call that did not settle keeps its own verdict; a cut parses what
// arrived and keeps the cut. Text the parser does not recognize — or a parse
// that panicked — fails the tier, which declines rather than guessing.
//
// A tier with no parser is its own text: the channel read it under the tier's
// cap already, so it is the body as it stands and there is nothing to read back.
func finishScript(result model.RunResult, script model.Script, cap model.RowCap) model.RunResult {
	if !result.Verdict.Settled() || script.Parse == nil {
		return result
	}
	if strings.TrimSpace(result.Stdout) == "" {
		return result
	}
	read, panicErr := fault.Result("script parse", func() scriptRead {
		set, err := script.Parse(result.Stdout)
		return scriptRead{set: set, err: err}
	})
	switch {
	case panicErr != nil:
		return model.RunResult{Verdict: model.VerdictFailed, Stderr: panicErr.Error(), ExitCode: 1}
	case read.err != nil:
		return model.RunResult{Verdict: model.VerdictFailed, Stderr: read.err.Error(), ExitCode: 1}
	case read.set == nil:
		return model.RunResult{
			Verdict:  model.VerdictFailed,
			Stderr:   "the parser recognized none of the tier's text",
			ExitCode: 1,
		}
	}
	parsed := result
	parsed.Records = read.set
	parsed.Stdout = ""
	return finishFields(parsed, cap)
}

// capLines keeps the first limit lines of a body and reports whether more
// followed. The boundary is the streaming harvest's: one probe past the limit
// decides, and a trailing newline is not another line. Keeping the two in step
// is what makes the in-process tier and the channel's own tiers mark the same
// body truncated, and keep the same text. The arithmetic is textutil.Head's,
// shared with the tiers that cap a body at a line count.
func capLines(text string, limit int) (string, bool) {
	return textutil.Head(text, limit)
}
