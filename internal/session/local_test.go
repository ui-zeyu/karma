package session

import (
	"strings"
	"testing"
	"time"
)

func TestRunLocalCapturesFullOutput(t *testing.T) {
	result := runLocal([]string{"/bin/sh", "-c", "seq 1 500"}, 10*time.Second, 0)
	if result.ExitCode != 0 || result.TimedOut || result.Truncated {
		t.Fatalf("should succeed completely: %+v", result)
	}
	if got := strings.Count(result.Stdout, "\n"); got != 500 {
		t.Fatalf("output should lose no lines: %d lines", got)
	}
}

func TestRunLocalLineLimitMarksTruncated(t *testing.T) {
	result := runLocal([]string{"/bin/sh", "-c", "seq 1 500"}, 10*time.Second, 50)
	if !result.Truncated || result.TimedOut {
		t.Fatalf("stopping the source at enough lines should mark truncated: %+v", result)
	}
	if result.ExitCode != 0 {
		t.Fatalf("truncation is this tier's answer and counts as success: %+v", result)
	}
	if got := strings.Count(result.Stdout, "\n"); got < 50 || got > 52 {
		t.Fatalf("should stop near the limit: %d lines", got)
	}
}

func TestRunLocalTimeoutKeepsPartialOutput(t *testing.T) {
	result := runLocal([]string{"/bin/sh", "-c", "echo first; sleep 5"}, 300*time.Millisecond, 0)
	if !result.TimedOut {
		t.Fatalf("should time out: %+v", result)
	}
	if !strings.Contains(result.Stdout, "first") {
		t.Fatalf("a timeout should keep output already produced: %q", result.Stdout)
	}
}

// stdout and stderr get the same treatment: stray output from the target is replaced with U+FFFD, so the body carries no bad bytes.
func TestRunLocalSanitizesBadBytes(t *testing.T) {
	result := runLocal([]string{"/bin/sh", "-c", "printf 'ok\\n\\377\\376bad\\n'"}, 5*time.Second, 0)
	if result.ExitCode != 0 {
		t.Fatalf("should succeed: %+v", result)
	}
	if !strings.Contains(result.Stdout, "ok\n") || !strings.Contains(result.Stdout, "\uFFFD") {
		t.Fatalf("bad bytes should be replaced with U+FFFD: %q", result.Stdout)
	}
}
