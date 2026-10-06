package session

import (
	"context"
	"strings"
	"testing"
	"time"

	"karma/internal/model"
)

func TestRunLocalCapturesFullOutput(t *testing.T) {
	result := runLocal(context.Background(), []string{"/bin/sh", "-c", "seq 1 500"}, 10*time.Second, model.RowCap{})
	if result.Verdict != model.VerdictAnswered || result.ExitCode != 0 || result.Truncated {
		t.Fatalf("should succeed completely: %+v", result)
	}
	if got := strings.Count(result.Stdout, "\n"); got != 500 {
		t.Fatalf("output should lose no lines: %d lines", got)
	}
}

func TestRunLocalScanCapMarksTruncated(t *testing.T) {
	result := runLocal(context.Background(), []string{"/bin/sh", "-c", "seq 1 500"}, 10*time.Second, model.Scan(50))
	if !result.Truncated || result.Verdict != model.VerdictAnswered {
		t.Fatalf("stopping the source at enough lines should mark truncated: %+v", result)
	}
	if result.Verdict != model.VerdictAnswered {
		t.Fatalf("truncation is this tier's answer and counts as success: %+v", result)
	}
	if got := strings.Count(result.Stdout, "\n"); got < 50 || got > 52 {
		t.Fatalf("should stop near the limit: %d lines", got)
	}
}

func TestRunLocalTimeoutKeepsPartialOutput(t *testing.T) {
	result := runLocal(context.Background(), []string{"/bin/sh", "-c", "echo first; sleep 5"}, 300*time.Millisecond, model.RowCap{})
	if result.Verdict != model.VerdictTimedOut {
		t.Fatalf("should time out: %+v", result)
	}
	if !strings.Contains(result.Stdout, "first") {
		t.Fatalf("a timeout should keep output already produced: %q", result.Stdout)
	}
}

// stdout and stderr get the same treatment: stray output from the target is replaced with U+FFFD, so the body carries no bad bytes.
func TestRunLocalSanitizesBadBytes(t *testing.T) {
	result := runLocal(context.Background(), []string{"/bin/sh", "-c", "printf 'ok\\n\\377\\376bad\\n'"}, 5*time.Second, model.RowCap{})
	if result.Verdict != model.VerdictAnswered {
		t.Fatalf("should succeed: %+v", result)
	}
	if !strings.Contains(result.Stdout, "ok\n") || !strings.Contains(result.Stdout, "\uFFFD") {
		t.Fatalf("bad bytes should be replaced with U+FFFD: %q", result.Stdout)
	}
}
