// The live observer: one progress line plus the panels, released in catalog
// order as the checks finish.

package render

import (
	"fmt"
	"io"
	"sync"
	"time"

	"karma/internal/model"
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// LiveObserver is the live observer: one progress line plus check panels
// released in catalog order, with an aspect banner drawn first when the aspect
// changes.
//
// One goroutine owns the terminal and all of the observer's state: the runner's
// workers only send events (CheckStarted and CheckFinished enqueue and never
// touch the writer), the ticker feeds the same queue, and nothing needs a lock.
// A finished check is taken into a table first and written back only when the
// catalog prefix is complete; a slow check ahead of it lets later ones pile up.
type LiveObserver struct {
	w        io.Writer
	maxLines int
	term     int
	tty      bool

	order    map[*model.Check]int
	events   chan observerEvent
	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}

	received map[int]*model.CheckResult
	next     int
	aspect   string

	total    int
	finished int
	current  string
	started  time.Time
	frame    int
}

// observerEvent is one message to the render loop.
type observerEvent struct {
	kind   eventKind
	check  *model.Check
	result *model.CheckResult
}
type eventKind int

const (
	startedEvent eventKind = iota
	finishedEvent
)

// progressInterval is the progress line's refresh cadence.
const progressInterval = 100 * time.Millisecond

// NewLiveObserver builds the observer. With tty false no progress line is
// drawn and panels are emitted in order.
func NewLiveObserver(w io.Writer, checks []*model.Check, maxLines, term int, tty bool) *LiveObserver {
	order := make(map[*model.Check]int, len(checks))
	for index, check := range checks {
		order[check] = index
	}
	return &LiveObserver{
		w:        w,
		maxLines: maxLines,
		term:     term,
		tty:      tty,
		order:    order,
		events:   make(chan observerEvent, 2*len(checks)+1),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
		received: map[int]*model.CheckResult{},
		total:    len(checks),
		started:  time.Now(),
	}
}

// Start launches the render loop.
func (o *LiveObserver) Start() {
	go o.loop()
}

// loop is the single owner of the terminal and the observer state: events
// apply here and nowhere else, so there is nothing to lock.
func (o *LiveObserver) loop() {
	defer func() {
		if o.tty { // the progress line leaves nothing behind
			fmt.Fprint(o.w, "\r\033[K")
		}
		close(o.done)
	}()
	var ticks <-chan time.Time
	if o.tty {
		ticker := time.NewTicker(progressInterval)
		defer ticker.Stop()
		ticks = ticker.C
	}
	for {
		select {
		case <-o.stop:
			o.drain()
			return
		case event := <-o.events:
			o.apply(event)
		case <-ticks:
			o.drawProgress()
		}
	}
}

// drain applies everything still queued: Close may fire while panels wait,
// and those panels are still due.
func (o *LiveObserver) drain() {
	for {
		select {
		case event := <-o.events:
			o.apply(event)
		default:
			return
		}
	}
}
func (o *LiveObserver) apply(event observerEvent) {
	switch event.kind {
	case startedEvent:
		o.current = string(event.check.Aspect) + " · " + event.check.ID
		o.drawProgress()
	case finishedEvent:
		o.finished++
		o.received[o.order[event.check]] = event.result
		o.flush()
	}
}

// CheckStarted queues the progress update.
func (o *LiveObserver) CheckStarted(check *model.Check) {
	o.events <- observerEvent{kind: startedEvent, check: check}
}

// CheckFinished queues the result; the loop releases the panels that are ready
// in catalog order.
func (o *LiveObserver) CheckFinished(check *model.Check, result *model.CheckResult) {
	o.events <- observerEvent{kind: finishedEvent, check: check, result: result}
}

// Close stops the loop and waits until every queued panel is on the wire. Call
// it after the run has joined, when no more events can arrive — the queue
// holds two events per check, so the send side never blocks.
func (o *LiveObserver) Close() {
	o.stopOnce.Do(func() { close(o.stop) })
	<-o.done
}
func (o *LiveObserver) flush() {
	for {
		result, ok := o.received[o.next]
		if !ok {
			return
		}
		delete(o.received, o.next)
		o.next++
		o.emit(result)
	}
}
func (o *LiveObserver) emit(result *model.CheckResult) {
	text, failed := renderPanel(result, o.maxLines, o.term)
	if text == "" && !failed { // no signal: stay silent
		return
	}
	// The progress line holds the current row; erase it before writing the
	// panel, or the spinner glyphs stick to the rail's first line.
	if o.tty {
		fmt.Fprint(o.w, "\r\033[K")
	}
	if aspect := string(result.Check.Aspect); aspect != o.aspect {
		o.aspect = aspect
		fmt.Fprintln(o.w, headingBand(aspect, o.term))
	}
	if text == "" {
		// Not even the fallback panel can be drawn: bare text with the check
		// name, rather than silently swallowing this check
		fmt.Fprintln(o.w, result.Check.ID+"  render failed")
		for _, row := range plainRows(result.Raw, result.Stderr, o.maxLines) {
			fmt.Fprintln(o.w, row)
		}
	} else {
		fmt.Fprintln(o.w, text)
	}
	fmt.Fprintln(o.w)
	o.drawProgress()
}
func (o *LiveObserver) drawProgress() {
	if !o.tty {
		return
	}
	frame := spinnerFrames[o.frame%len(spinnerFrames)]
	o.frame++
	line := fmt.Sprintf("\r\033[K%s %d/%d %s %s",
		accentStyle.seq().Render(frame),
		o.finished, o.total,
		mutedStyle.seq().Render(o.current),
		mutedStyle.seq().Render(time.Since(o.started).Round(time.Second).String()))
	fmt.Fprint(o.w, line)
}
