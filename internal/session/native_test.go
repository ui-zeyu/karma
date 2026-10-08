package session

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"karma/internal/model"
)

func TestRunNativeSuccess(t *testing.T) {
	t.Parallel()
	res := runCall(context.Background(), LocalSession{},
		model.Native{Body: func(context.Context) (string, error) { return "hello\n", nil }}, 0, model.RowCap{})
	if res.Verdict != model.VerdictAnswered || res.Stdout != "hello\n" || res.Truncated {
		t.Fatalf("wanted exit 0 with the body, got %+v", res)
	}
}

func TestRunNativeUnavailableFallsThroughLikeAMissingBinary(t *testing.T) {
	t.Parallel()
	res := runCall(context.Background(), LocalSession{},
		model.Native{Body: func(context.Context) (string, error) { return "", model.ErrTierUnavailable }}, 0, model.RowCap{})
	if res.Verdict != model.VerdictUnavailable || res.ExitCode != 127 {
		t.Fatalf("an unavailable native tier should read as unavailable/127, got %+v", res)
	}
}

func TestRunNativeErrorReportsStderr(t *testing.T) {
	t.Parallel()
	res := runCall(context.Background(), LocalSession{},
		model.Native{Body: func(context.Context) (string, error) { return "", errors.New("boom") }}, 0, model.RowCap{})
	if res.Verdict != model.VerdictFailed || res.ExitCode != 1 || res.Stderr != "boom" {
		t.Fatalf("wanted exit 1 with the error on stderr, got %+v", res)
	}
}

// A body parses whatever the target holds, and it runs on its own goroutine,
// outside the runner's recover: an unrecovered panic there would end the
// process and lose the whole report. It fails as one tier instead.
func TestRunNativeSurvivesAPanickingBody(t *testing.T) {
	t.Parallel()
	res := runCall(context.Background(), LocalSession{},
		model.Native{Body: func(context.Context) (string, error) {
			var empty []byte
			return string(empty[1:]), nil // the shape an unguarded slice takes
		}}, 0, model.RowCap{})
	if res.Verdict != model.VerdictFailed || !strings.Contains(res.Stderr, "in-process tier") {
		t.Fatalf("wanted a failed tier naming the panic, got %+v", res)
	}
}

func TestRunNativeTimeoutKeepsPartialOutput(t *testing.T) {
	t.Parallel()
	res := runCall(context.Background(), LocalSession{},
		model.Native{Body: func(ctx context.Context) (string, error) {
			<-ctx.Done()
			return "partial", ctx.Err()
		}}, 10*time.Millisecond, model.RowCap{})
	if res.Verdict != model.VerdictTimedOut || res.ExitCode != -1 || res.Stdout != "partial" {
		t.Fatalf("wanted a timed-out result with the partial body, got %+v", res)
	}
}

func TestRunNativeCancelKeepsPartialOutput(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.AfterFunc(10*time.Millisecond, cancel)
	res := runCall(ctx, LocalSession{},
		model.Native{Body: func(ctx context.Context) (string, error) {
			<-ctx.Done()
			return "partial", ctx.Err()
		}}, 5*time.Second, model.RowCap{})
	if res.Verdict != model.VerdictInterrupted || res.Stdout != "partial" {
		t.Fatalf("wanted an interrupted result with the partial body, got %+v", res)
	}
}

// The deadline is enforced rather than offered: a body parked in a syscall has
// no context to observe, so the caller must stop waiting by itself. Before
// this, such a body parked the whole collection — no signal could break it.
func TestRunNativeAbandonsABodyThatIgnoresTheDeadline(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	started := time.Now()
	res := runCall(context.Background(), LocalSession{},
		model.Native{Body: func(context.Context) (string, error) {
			<-release // the shape of an open(2) waiting for a writer
			return "late", nil
		}}, 20*time.Millisecond, model.RowCap{})
	if res.Verdict != model.VerdictTimedOut || res.ExitCode != -1 || res.Stdout != "" {
		t.Fatalf("wanted a bare timeout, got %+v", res)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("the caller waited %s for a body stuck in a syscall", elapsed)
	}
}

// The same body under a cancelled run reads as interrupted, which is what
// Ctrl-C must mean: the operator ended the run, not the target's clock.
func TestRunNativeAbandonsABodyThatIgnoresTheCancel(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	time.AfterFunc(20*time.Millisecond, cancel)
	res := runCall(ctx, LocalSession{},
		model.Native{Body: func(context.Context) (string, error) {
			<-release
			return "late", nil
		}}, time.Minute, model.RowCap{})
	if res.Verdict != model.VerdictInterrupted {
		t.Fatalf("wanted an interrupted result, got %+v", res)
	}
}

func TestRunNativeScanCapTruncates(t *testing.T) {
	t.Parallel()
	res := runCall(context.Background(), LocalSession{},
		model.Native{Body: func(context.Context) (string, error) {
			return "a\nb\nc\nd", nil
		}}, 0, model.Scan(2))
	if res.Verdict != model.VerdictAnswered || res.Stdout != "a\nb\n" || !res.Truncated {
		t.Fatalf("wanted the first two lines marked truncated, got %+v", res)
	}
}

// The in-process cap shares the streaming harvest's boundary: the body keeps
// each line's own newline, a body that ends at the limit is the whole answer,
// and a partial last line counts as content. The two channels therefore mark
// the same body truncated and hand the reader the same text.
func TestCapLinesMatchesTheHarvestBoundary(t *testing.T) {
	t.Parallel()
	cases := []struct {
		text      string
		limit     int
		want      string
		truncated bool
	}{
		{"a\nb\n", 2, "a\nb\n", false},
		{"a\nb", 2, "a\nb", false},
		{"a\nb\nc\n", 2, "a\nb\n", true},
		{"a\nb\nc", 2, "a\nb\n", true},
		{"", 2, "", false},
		{"\n", 1, "\n", false},
		{"a\nb\nc\n", 0, "a\nb\nc\n", false},
	}
	for _, c := range cases {
		got, truncated := capLines(c.text, c.limit)
		if got != c.want || truncated != c.truncated {
			t.Errorf("capLines(%q, %d) = %q, %v; want %q, %v",
				c.text, c.limit, got, truncated, c.want, c.truncated)
		}
	}
}
