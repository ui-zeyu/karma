// How an invocation kind runs, stated once: the kinds whose bodies are karma's
// own code run in process, and the kinds that stand for shell text run through
// the channel's shell front. A channel supplies that front and nothing else, so
// the set of kinds lives in model and this switch alone — a new kind is added
// beside the others instead of once per channel.

package session

import (
	"context"

	"karma/internal/model"
)

// shellTier is the channel's front for a call that stands for shell text: it
// renders the invocation the channel's way and harvests it under the cap. The
// local channel execs a Command without a shell and wraps everything else in
// /bin/sh -c; a remote channel sends one command string to the target.
type shellTier func(ctx context.Context, inv model.Invocation, cap model.RowCap) model.RunResult

// dispatch is the one statement of how an invocation kind becomes a run. The
// kinds that run in process are the same on every channel (only the local one is
// ever asked for them), and every other kind is shell text the channel carries.
// p is the channel's own waiting, resolved: an in-process body gets its grace.
func dispatch(ctx context.Context, inv model.Invocation, cap model.RowCap, p pace, shell shellTier) model.RunResult {
	p = p.resolved()
	switch kind := inv.(type) {
	case model.Native:
		return runNative(ctx, kind.Body, cap, p)
	case model.Fields:
		return runFields(ctx, kind.Read, cap, p)
	case model.Script:
		call := scriptCall(kind, cap)
		return finishScript(shell(ctx, call.Inv, call.Cap), kind, cap)
	case model.Command, model.Shell:
		return shell(ctx, inv, cap)
	}
	return noShellFor(inv)
}
