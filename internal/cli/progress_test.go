package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	chrome "karma/internal/panel"
)

func TestProgressLineCountsTheSeconds(t *testing.T) {
	line := progressLine("COLLECTING PROCESSES", 12*time.Second, 60)
	plain := chrome.StripANSI(line)
	if !strings.Contains(plain, " COLLECTING PROCESSES") {
		t.Fatalf("line = %q, want the stage label", plain)
	}
	if !strings.HasSuffix(plain, " 12.0s ") {
		t.Fatalf("line = %q, want the clock on the right edge", plain)
	}
	if width := chrome.DisplayWidth(plain) - 1; width != 59 {
		t.Fatalf("line spans %d columns, want 59 (the terminal minus one)", width)
	}
	if line := progressLine("COLLECTING STARTUP", 300*time.Millisecond, 60); !strings.Contains(chrome.StripANSI(line), " 0.3s ") {
		t.Fatalf("sub-second line = %q, want a 0.3s clock", chrome.StripANSI(line))
	}
}

func TestProgressPaintsStagesAndWipesOnDone(t *testing.T) {
	var buf bytes.Buffer
	p := &progress{w: &buf, width: 60, stop: make(chan struct{})}
	p.stage("startup")
	if line := chrome.StripANSI(buf.String()); !strings.Contains(line, " COLLECTING STARTUP") {
		t.Fatalf("first paint = %q", line)
	}
	buf.Reset()
	p.stage("processes")
	if line := chrome.StripANSI(buf.String()); !strings.Contains(line, " COLLECTING PROCESSES") {
		t.Fatalf("second paint = %q", line)
	}
	buf.Reset()
	p.done()
	if got := buf.String(); got != "\r\x1b[K" {
		t.Fatalf("done wrote %q, want a plain wipe", got)
	}
	p.done() // a second done is a no-op
	if got := buf.String(); got != "\r\x1b[K" {
		t.Fatalf("second done wrote %q", got)
	}
}

// TestProgressCancelRepaints pins the interrupt state: the line turns to
// CANCELLING at once and later stage reports cannot overwrite it.
func TestProgressCancelRepaints(t *testing.T) {
	var buf bytes.Buffer
	p := &progress{w: &buf, width: 60, stop: make(chan struct{})}
	p.stage("packages")
	buf.Reset()
	p.cancel()
	if line := chrome.StripANSI(buf.String()); !strings.Contains(line, " CANCELLING") {
		t.Fatalf("cancel paint = %q", line)
	}
	buf.Reset()
	p.stage("web")
	if line := chrome.StripANSI(buf.String()); !strings.Contains(line, " CANCELLING") {
		t.Fatalf("post-cancel paint = %q", line)
	}
	p.done()
}

func TestProgressToleratesNil(t *testing.T) {
	var p *progress
	p.stage("catalog")
	p.cancel()
	p.watch(context.Background())
	p.done()
	if got := stageProgress(nil); got != nil {
		t.Fatalf("stageProgress(nil) = %v, want nil", got)
	}
}

func TestNewProgressStaysQuietForJSON(t *testing.T) {
	// go test runs with a piped stderr, so the terminal gate answers nil too;
	// the JSON branch must answer nil regardless of the terminal.
	if p := newProgress(true); p != nil {
		t.Fatalf("newProgress(json) = %v, want nil", p)
	}
	if p := newProgress(false); p != nil {
		t.Fatalf("newProgress on a piped stderr = %v, want nil", p)
	}
}
