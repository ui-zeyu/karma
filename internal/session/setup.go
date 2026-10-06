// Channel-library setup steps: the calls karma makes into a channel library
// that has no context to give them.
//
// Two of them exist — the ssh library's session open and exec request, and its
// upload command — and a target that accepts a connection and then goes silent
// inside one would block past every deadline the operator set, and past Ctrl-C
// too: no part of the call is watching the context yet. So the step runs on its
// own goroutine and the caller stops waiting on it. The context ending is the
// call's own cut; outliving the bound means the transport stopped answering,
// which the caller reads as a lost channel. The goroutine stays parked on its
// request and closing the connection is what releases it.

package session

import (
	"context"
	"errors"
	"time"

	"karma/internal/fault"
)

// errSetupUnanswered is a setup step that outlived its bound: the transport took
// the connection and then stopped answering.
var errSetupUnanswered = errors.New("the target stopped answering")

// setup runs one context-less library step under the call's deadline and a fixed
// bound. It returns the step's own value and error, the context's error when the
// deadline or a cancel ended the wait, or errSetupUnanswered when the step
// outlived the bound. boundary is the name a panic in the step is reported
// under.
func setup[T any](ctx context.Context, boundary string, bound time.Duration, step func() (T, error)) (T, error) {
	type outcome struct {
		value T
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		result, problem := fault.Result(boundary, func() outcome {
			value, err := step()
			return outcome{value: value, err: err}
		})
		if problem != nil {
			// A panic is this step failing, not the process ending: the caller
			// reads it like any other error of the step.
			result = outcome{err: problem}
		}
		done <- result
	}()
	timer := time.NewTimer(bound)
	defer timer.Stop()
	select {
	case result := <-done:
		return result.value, result.err
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	case <-timer.C:
		var zero T
		return zero, errSetupUnanswered
	}
}

// setupErr is setup for a step whose only product is its error.
func setupErr(ctx context.Context, boundary string, bound time.Duration, step func() error) error {
	_, err := setup(ctx, boundary, bound, func() (struct{}, error) { return struct{}{}, step() })
	return err
}
