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

	truncated := false
	if lineLimit > 0 {
		var b strings.Builder
		for i, line := range strings.Split(text, "\n") {
			if i == lineLimit {
				truncated = true
				break
			}
			if i > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(line)
		}
		text = b.String()
	}
	if int64(len(text)) > maxHarvestBytes {
		text = text[:maxHarvestBytes]
		truncated = true
	}
	return model.RunResult{Stdout: validText(text), ExitCode: 0, Truncated: truncated}
}
