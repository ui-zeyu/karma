// The collection progress line: one updating stderr line drawn as the
// report's own panel head, so a long collection never reads as a hang.

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"karma/internal/audit"
	chrome "karma/internal/panel"
)

// progressTick is how often the line repaints while one stage runs; the
// displayed clock steps by 0.1s.
const progressTick = 100 * time.Millisecond

// progress paints one full-width status band on stderr — grey rail, the
// stage name on the left, the elapsed clock on the right edge, the same head
// an evidence panel wears. It is nil for a JSON run or a piped stderr, where
// the line would be noise in the output or the log; every method tolerates a
// nil receiver.
type progress struct {
	w         io.Writer
	width     int
	mu        sync.Mutex
	current   string
	cancelled bool
	finished  bool
	start     time.Time
	begun     bool
	tick      *time.Ticker
	stop      chan struct{}
}

// newProgress answers the stderr reporter, or nil when the run must stay
// quiet: JSON output, or a stderr that is not a terminal.
func newProgress(json bool) *progress {
	if json || !isTerminal(os.Stderr) {
		return nil
	}
	return &progress{w: os.Stderr, width: terminalWidth(os.Stderr), stop: make(chan struct{})}
}

// watch turns the line to CANCELLING as soon as the run's context is
// canceled, so an interrupt shows up before the collectors have drained.
func (p *progress) watch(ctx context.Context) {
	if p == nil {
		return
	}
	go func() {
		select {
		case <-ctx.Done():
			p.cancel()
		case <-p.stop:
		}
	}()
}

// stage reports the collector's current stage and starts the repaint ticker
// on the first call. The paint holds the lock with the ticker's repaint, so
// the writer never sees interleaved lines.
func (p *progress) stage(name string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished {
		return
	}
	if !p.begun {
		p.begun = true
		p.start = time.Now()
		p.tick = time.NewTicker(progressTick)
		go p.loop()
	}
	p.current = name
	p.paintLocked()
}

// cancel repaints the line as CANCELLING; later stages keep that label.
func (p *progress) cancel() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished || p.cancelled {
		return
	}
	p.cancelled = true
	if p.begun {
		p.paintLocked()
	}
}

// loop repaints the line while one stage runs, so the clock keeps counting.
// The ticker and stop channel are captured under the lock: done may nil and
// close them while this goroutine is still starting.
func (p *progress) loop() {
	p.mu.Lock()
	tick, stop := p.tick, p.stop
	p.mu.Unlock()
	if tick == nil {
		return
	}
	for {
		select {
		case <-tick.C:
			p.mu.Lock()
			p.paintLocked()
			p.mu.Unlock()
		case <-stop:
			return
		}
	}
}

// paintLocked draws the band; the caller holds the lock.
func (p *progress) paintLocked() {
	label := "COLLECTING " + strings.ToUpper(p.current)
	if p.cancelled {
		label = "CANCELLING"
	}
	fmt.Fprint(p.w, progressLine(label, time.Since(p.start), p.width))
}

// done stops the ticker and wipes the line, so the report starts on a clean
// display. It is safe to call twice and on a nil receiver.
func (p *progress) done() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished {
		return
	}
	p.finished = true
	if p.tick != nil {
		p.tick.Stop()
		p.tick = nil
	}
	close(p.stop)
	fmt.Fprint(p.w, "\r\x1b[K")
}

// progressLine draws one status band: the label on the left, the elapsed
// clock on the right edge, behind the report's grey rail.
func progressLine(label string, elapsed time.Duration, width int) string {
	clock := fmt.Sprintf(" %.1fs ", elapsed.Seconds())
	head := chrome.Band(" "+label, clock, width-2, chrome.SubBandBG, chrome.SubBandFG, false, true)
	return "\r\x1b[K" + chrome.Rail(head, nil, width, chrome.MutedColor, true)
}

// stageProgress adapts a progress to the collector's audit.Progress hook.
func stageProgress(p *progress) audit.Progress {
	if p == nil {
		return nil
	}
	return p.stage
}
