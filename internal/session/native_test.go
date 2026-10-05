package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"karma/internal/model"
)

func TestRunNativeSuccess(t *testing.T) {
	res := LocalSession{}.Run(context.Background(),
		model.Dual{Run: func(context.Context) (string, error) { return "hello\n", nil }}, 0, 0)
	if res.ExitCode != 0 || res.Stdout != "hello\n" || res.Truncated {
		t.Fatalf("wanted exit 0 with the body, got %+v", res)
	}
}

func TestRunNativeUnavailableFallsThroughLikeAMissingBinary(t *testing.T) {
	res := LocalSession{}.Run(context.Background(),
		model.Dual{Run: func(context.Context) (string, error) { return "", model.ErrTierUnavailable }}, 0, 0)
	if res.ExitCode != 127 {
		t.Fatalf("unavailable native tier should read as 127, got %+v", res)
	}
}

// A body that cannot answer on this host yields to the tier's script side: the
// local channel then answers the way the ssh channel would (a non-Linux host
// runs the host's ps, df, last).
func TestRunNativeUnavailableFallsBackToTheScript(t *testing.T) {
	res := LocalSession{}.Run(context.Background(),
		model.Dual{
			Run:    func(context.Context) (string, error) { return "", model.ErrTierUnavailable },
			Script: "echo from-script",
		}, 10*time.Second, 0)
	if res.ExitCode != 0 || res.Stdout != "from-script\n" {
		t.Fatalf("wanted the script side's answer, got %+v", res)
	}
}

// An answered body is the answer: the script side does not run.
func TestRunNativeAnsweredBodySkipsTheScript(t *testing.T) {
	res := LocalSession{}.Run(context.Background(),
		model.Dual{
			Run:    func(context.Context) (string, error) { return "in-process\n", nil },
			Script: "echo from-script",
		}, 10*time.Second, 0)
	if res.Stdout != "in-process\n" {
		t.Fatalf("wanted the in-process body, got %+v", res)
	}
}

// The fallback runs the script once: a script that is itself missing stays the
// 127 the runner reads as an unavailable tier.
func TestRunNativeFallbackDoesNotRetryTheBody(t *testing.T) {
	res := LocalSession{}.Run(context.Background(),
		model.Dual{
			Run:    func(context.Context) (string, error) { return "", model.ErrTierUnavailable },
			Script: "exit 127",
		}, 10*time.Second, 0)
	if res.ExitCode != 127 {
		t.Fatalf("wanted the script's own 127, got %+v", res)
	}
}

func TestRunNativeErrorReportsStderr(t *testing.T) {
	res := LocalSession{}.Run(context.Background(),
		model.Dual{Run: func(context.Context) (string, error) { return "", errors.New("boom") }}, 0, 0)
	if res.ExitCode != 1 || res.Stderr != "boom" {
		t.Fatalf("wanted exit 1 with the error on stderr, got %+v", res)
	}
}

func TestRunNativeTimeoutKeepsPartialOutput(t *testing.T) {
	res := LocalSession{}.Run(context.Background(),
		model.Dual{Run: func(ctx context.Context) (string, error) {
			<-ctx.Done()
			return "partial", ctx.Err()
		}}, 10*time.Millisecond, 0)
	if !res.TimedOut || res.ExitCode != -1 || res.Stdout != "partial" {
		t.Fatalf("wanted a timed-out result with the partial body, got %+v", res)
	}
}

func TestRunNativeCancelKeepsPartialOutput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.AfterFunc(10*time.Millisecond, cancel)
	res := LocalSession{}.Run(ctx,
		model.Dual{Run: func(ctx context.Context) (string, error) {
			<-ctx.Done()
			return "partial", ctx.Err()
		}}, 5*time.Second, 0)
	if !res.Interrupted || res.Stdout != "partial" {
		t.Fatalf("wanted an interrupted result with the partial body, got %+v", res)
	}
}

func TestRunNativeLineLimitTruncates(t *testing.T) {
	res := LocalSession{}.Run(context.Background(),
		model.Dual{Run: func(context.Context) (string, error) {
			return "a\nb\nc\nd", nil
		}}, 0, 2)
	if res.Stdout != "a\nb" || !res.Truncated {
		t.Fatalf("wanted the first two lines marked truncated, got %+v", res)
	}
}
