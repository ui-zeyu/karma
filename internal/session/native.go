// In-process tier glue: the local channel runs a Dual tier's Run body inside
// karma itself. Result semantics mirror a subprocess tier: timeout and
// cancellation keep the partial text, ErrTierUnavailable maps to the
// missing-binary 127 so the probe chain falls through, and the line and byte
// caps mirror harvest's.

package session

import (
	"context"
	"errors"
	"strings"
	"time"

	"karma/internal/model"
)

func runNative(ctx context.Context, fn func(context.Context) (string, error), timeout time.Duration, lineLimit int) model.RunResult {
	if fn == nil {
		// A Dual with no local branch is a tier that exists on the ssh channel
		// only (model.Dual.For): the runner never routes it here, and a caller
		// that does gets the same answer a body that cannot run would give, so
		// LocalSession.Run falls to the tier's script side as it does for every
		// other unavailable body.
		return model.RunResult{Stderr: model.ErrTierUnavailable.Error(), ExitCode: 127}
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	text, err := fn(ctx)
	switch {
	case err == nil:
	case errors.Is(err, model.ErrTierUnavailable):
		return model.RunResult{Stderr: err.Error(), ExitCode: 127}
	case errors.Is(err, context.DeadlineExceeded):
		return model.RunResult{Stdout: validText(text), ExitCode: -1, TimedOut: true}
	case ctx.Err() != nil:
		return model.RunResult{Stdout: validText(text), ExitCode: -1, Interrupted: true}
	default:
		return model.RunResult{Stderr: err.Error(), ExitCode: 1}
	}

	text, truncated := capLines(text, lineLimit)
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
// body truncated, and keep the same text.
//
// SplitN stops one line past the cap, so a body of a million lines costs the
// cap rather than a slice entry per line.
func capLines(text string, limit int) (string, bool) {
	if limit <= 0 {
		return text, false
	}
	lines := strings.SplitN(strings.TrimSuffix(text, "\n"), "\n", limit+1)
	if len(lines) <= limit {
		return text, false
	}
	return strings.Join(lines[:limit], "\n") + "\n", true
}
