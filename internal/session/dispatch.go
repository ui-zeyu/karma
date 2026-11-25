// How an invocation becomes a run: Shell is the only kind the audit sends, so
// every channel renders it through its own shell front.

package session

import (
	"context"

	"karma/internal/model"
)

// shellTier is the channel's front for a call: it renders the script the
// channel's way and harvests it under the cap.
type shellTier func(ctx context.Context, inv model.Invocation, cap model.RowCap) model.RunResult

func dispatch(ctx context.Context, inv model.Invocation, cap model.RowCap, shell shellTier) model.RunResult {
	if _, ok := inv.(model.Shell); ok {
		return shell(ctx, inv, cap)
	}
	return noShellFor(inv)
}
