// In-process tier glue: the local channel runs a Dual tier's Run body inside
// karma itself. Result semantics mirror a subprocess tier: timeout and
// cancellation keep the partial text, ErrTierUnavailable maps to the
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
	"fmt"
	"time"

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

func runNative(ctx context.Context, fn func(context.Context) (string, error), timeout time.Duration, lineLimit int) model.RunResult {
	if fn == nil {
		// A Dual with no local branch is a tier that exists on the ssh channel
		// only (model.Dual.For): the runner never routes it here, and a caller
		// that does gets the same answer a body that cannot run would give, so
		// LocalSession.Run falls to the tier's script side as it does for every
		// other unavailable body.
		return model.RunResult{Stderr: model.ErrTierUnavailable.Error(), ExitCode: 127}
	}
	bodyCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		bodyCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	// Buffered: an abandoned body must never block on its own send.
	done := make(chan nativeResult, 1)
	go func() {
		// A body parses whatever the target holds, and this goroutine is
		// outside the runner's own recover: an unrecovered panic here ends the
		// process and takes the whole report with it, where the contract is
		// that one broken check fails alone.
		defer func() {
			if problem := recover(); problem != nil {
				done <- nativeResult{err: fmt.Errorf("in-process tier panicked: %v", problem)}
			}
		}()
		text, err := fn(bodyCtx)
		done <- nativeResult{text: text, err: err}
	}()
	select {
	case result := <-done:
		return finishNative(result, ctx, lineLimit)
	case <-bodyCtx.Done():
		select {
		case result := <-done:
			return finishNative(result, ctx, lineLimit)
		case <-time.After(bodyGrace):
		}
		// The body is behind a syscall that ignores the context. Report the
		// deadline and leave the goroutine where it is: it holds nothing the
		// report needs, and the process exits without waiting for it.
		if ctx.Err() != nil {
			return model.RunResult{ExitCode: -1, Interrupted: true}
		}
		return model.RunResult{ExitCode: -1, TimedOut: true}
	}
}

// finishNative turns one finished body into the tier's result. ctx is the
// caller's own context, so Interrupted means the operator cancelled the run
// rather than a body that noticed someone else's deadline.
func finishNative(result nativeResult, ctx context.Context, lineLimit int) model.RunResult {
	switch {
	case result.err == nil:
	case errors.Is(result.err, model.ErrTierUnavailable):
		return model.RunResult{Stderr: result.err.Error(), ExitCode: 127}
	case errors.Is(result.err, context.DeadlineExceeded):
		return model.RunResult{Stdout: validText(result.text), ExitCode: -1, TimedOut: true}
	case ctx.Err() != nil:
		return model.RunResult{Stdout: validText(result.text), ExitCode: -1, Interrupted: true}
	default:
		return model.RunResult{Stderr: result.err.Error(), ExitCode: 1}
	}

	text, truncated := capLines(result.text, lineLimit)
	if int64(len(text)) > maxHarvestBytes {
		text = text[:maxHarvestBytes]
		truncated = true
	}
	return model.RunResult{Stdout: validText(text), ExitCode: 0, Truncated: truncated}
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
