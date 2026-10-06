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
	"time"

	"karma/internal/fault"
	"karma/internal/model"
	"karma/internal/textutil"
)

// bodyGrace is how long a body that is already unwinding (every walk checks the
// context) has to hand back its partial answer before the caller abandons it.
const bodyGrace = 250 * time.Millisecond

// nativeResult is one finished in-process body.
type nativeResult struct {
	text string
	err  error
}

func runNative(ctx context.Context, fn func(context.Context) (string, error), cap model.RowCap) model.RunResult {
	if fn == nil {
		// A Native with no body is a catalog mistake rather than a target's
		// answer; it reads as a tier that cannot run here, which the chain in
		// the runner falls through.
		return model.RunResult{Verdict: model.VerdictUnavailable, Stderr: model.ErrTierUnavailable.Error(), ExitCode: 127}
	}
	// Buffered: an abandoned body must never block on its own send.
	done := make(chan nativeResult, 1)
	go func() {
		// A body parses whatever the target holds, and this goroutine is
		// outside the runner's own boundary: a panic here goes through fault,
		// so one broken tier fails alone instead of ending the report.
		result, err := fault.Result("in-process tier", func() nativeResult {
			text, err := fn(ctx)
			return nativeResult{text: text, err: err}
		})
		if err != nil {
			result = nativeResult{err: err}
		}
		done <- result
	}()
	select {
	case result := <-done:
		return finishNative(result, cap)
	case <-ctx.Done():
		select {
		case result := <-done:
			return finishNative(result, cap)
		case <-time.After(bodyGrace):
		}
		// The body is behind a syscall that ignores the context. Report the cut
		// and leave the goroutine where it is: it holds nothing the report
		// needs, and the process exits without waiting for it.
		return model.RunResult{Verdict: cutVerdict(ctx), ExitCode: -1}
	}
}

// finishNative turns one finished body into the tier's result. The body's
// context is the call's own, so a context error it reports is either this
// call's deadline or the operator's cancellation — the same two endings every
// other tier reports, read from the same place.
func finishNative(result nativeResult, cap model.RowCap) model.RunResult {
	switch {
	case result.err == nil:
	case errors.Is(result.err, model.ErrTierUnavailable):
		return model.RunResult{Verdict: model.VerdictUnavailable, Stderr: result.err.Error(), ExitCode: 127}
	case errors.Is(result.err, context.DeadlineExceeded):
		return model.RunResult{Verdict: model.VerdictTimedOut, Stdout: validText(result.text), ExitCode: -1}
	case errors.Is(result.err, context.Canceled):
		return model.RunResult{Verdict: model.VerdictInterrupted, Stdout: validText(result.text), ExitCode: -1}
	default:
		return model.RunResult{Verdict: model.VerdictFailed, Stderr: result.err.Error(), ExitCode: 1}
	}

	text, truncated := capLines(result.text, cap.Rows)
	if int64(len(text)) > maxHarvestBytes {
		text = text[:maxHarvestBytes]
		truncated = true
	}
	return model.RunResult{Verdict: model.VerdictAnswered, Stdout: validText(text), Truncated: truncated}
}

// capLines keeps the first limit lines of a body and reports whether more
// followed. The boundary is the streaming harvest's: one probe past the limit
// decides, and a trailing newline is not another line. Keeping the two in step
// is what makes the in-process tier and the subprocess/ssh tiers mark the same
// body truncated, and keep the same text. The arithmetic is textutil.Head's,
// shared with the tiers that cap a body at a line count.
func capLines(text string, limit int) (string, bool) {
	return textutil.Head(text, limit)
}
