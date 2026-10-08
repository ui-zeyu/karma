package session

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"karma/internal/model"
)

// fakeChunk is one readLine response: ok=false with non-empty text is a trailing partial line without a newline.
type fakeChunk struct {
	text string
	ok   bool
}

// fakeSource replays a scripted chunk list. read overrides the replay, for the
// paths that need a read to misbehave; onWait and onStop are the hooks the
// waiver paths reach into.
type fakeSource struct {
	baseSource
	chunks []fakeChunk
	index  int
	read   func() (string, bool)
	onWait func()
	onStop func()
}

func fakeSourceOf(chunks ...fakeChunk) *fakeSource { return fakeSourceCapped(0, chunks) }

// fakeSourceCapped is a source with the byte safety valve tightened, so the cap
// is reachable in a test.
func fakeSourceCapped(byteLimit int64, chunks []fakeChunk) *fakeSource {
	return &fakeSource{baseSource: baseSource{limit: byteLimit}, chunks: chunks}
}

func (f *fakeSource) wait() {
	if f.onWait != nil {
		f.onWait()
	}
}

func (f *fakeSource) stop() {
	if f.onStop != nil {
		f.onStop()
	}
}

func (f *fakeSource) readLine() (string, bool) {
	if f.read != nil {
		return f.read()
	}
	return f.next()
}

// next replays one scripted chunk.
func (f *fakeSource) next() (string, bool) {
	if f.index >= len(f.chunks) {
		return "", false
	}
	chunk := f.chunks[f.index]
	f.index++
	return chunk.text, chunk.ok
}

func (f *fakeSource) readAll() string { return "" }

func (f *fakeSource) exitCode() int { return 0 }

func line(text string) fakeChunk { return fakeChunk{text: text, ok: true} }
func tail(text string) fakeChunk { return fakeChunk{text: text, ok: false} } // last line without a newline

// streamingSource produces lines until stopped and keeps readLine hanging after
// the stop, so both stop paths run through the grace period. Callers state a
// short pace (quickPace).
type streamingSource struct {
	baseSource
	stopped chan struct{}
	once    sync.Once
}

func (s *streamingSource) wait() {}

func (s *streamingSource) stop() { s.once.Do(func() { close(s.stopped) }) }

func (s *streamingSource) readLine() (string, bool) {
	select {
	case <-s.stopped:
		<-make(chan struct{}) // a pathological source: reads hang past the stop
		return "", false
	default:
	}
	return "row\n", true
}

func (s *streamingSource) readAll() string { return "" }

func (s *streamingSource) exitCode() int { return -1 }

func newStreamingSource() *streamingSource {
	return &streamingSource{stopped: make(chan struct{})}
}

// stuckSource ignores stop entirely: after its first row it parks in a read that
// only the test's own release ends, so the grace period is what finishes the
// call — the shape of a channel whose stop cannot release its reads.
type stuckSource struct {
	baseSource
	reads   int
	release chan struct{}
}

func newStuckSource() *stuckSource { return &stuckSource{release: make(chan struct{})} }

func (s *stuckSource) wait() {}

func (s *stuckSource) stop() {}

func (s *stuckSource) readLine() (string, bool) {
	s.reads++
	if s.reads == 1 {
		return "early\n", true
	}
	<-s.release
	return "", false
}

func (s *stuckSource) readAll() string { return "" }

func (s *stuckSource) exitCode() int { return -1 }

// quickPace is the channel's waiting in milliseconds: the behavior these tests
// state is the same, only the waiting is not. Nothing here mutates a package
// variable, so the tests of this package run beside each other.
func quickPace() pace {
	return pace{cutGrace: 50 * time.Millisecond, bodyGrace: 10 * time.Millisecond}
}

// harvestFor is one harvest under a budget, stated the way the runner states it:
// the deadline travels in the context, so the source and the channel setup share
// it.
func harvestFor(t *testing.T, src source, budget time.Duration, cap model.RowCap) model.RunResult {
	t.Helper()
	ctx, cancel := Within(context.Background(), budget)
	defer cancel()
	return harvest(ctx, src, cap, quickPace())
}

func TestHarvestScanCapCleanEOF(t *testing.T) {
	t.Parallel()
	src := fakeSourceOf(line("a\n"), line("b\n"), line("c\n"))
	result := harvestFor(t, src, 2*time.Second, model.Scan(3))
	if result.Truncated {
		t.Errorf("EOF exactly at the limit does not count as truncated")
	}
	if result.Verdict != model.VerdictAnswered {
		t.Errorf("a clean EOF is the tier's answer, got %v", result.Verdict)
	}
	if result.Stdout != "a\nb\nc\n" {
		t.Errorf("body = %q", result.Stdout)
	}
}

func TestHarvestScanCapTruncated(t *testing.T) {
	t.Parallel()
	src := fakeSourceOf(line("a\n"), line("b\n"), line("c\n"), line("d\n"))
	result := harvestFor(t, src, 2*time.Second, model.Scan(3))
	if !result.Truncated {
		t.Errorf("a complete line after the limit should mark truncated")
	}
	if result.Stdout != "a\nb\nc\n" {
		t.Errorf("body = %q", result.Stdout)
	}
}

// A trailing partial line has more=false but non-empty content: the truncated flag was once missed because the condition included more.
func TestHarvestScanCapPartialTail(t *testing.T) {
	t.Parallel()
	src := fakeSourceOf(line("a\n"), line("b\n"), line("c\n"), tail("partial"))
	result := harvestFor(t, src, 2*time.Second, model.Scan(3))
	if !result.Truncated {
		t.Errorf("a trailing partial line after the limit should mark truncated")
	}
	if result.Stdout != "a\nb\nc\n" {
		t.Errorf("body = %q", result.Stdout)
	}
}

func TestHarvestByteCap(t *testing.T) {
	t.Parallel()
	src := fakeSourceCapped(8, []fakeChunk{line("12345678\n"), line("x\n")})
	result := harvestFor(t, src, 2*time.Second, model.RowCap{})
	if !result.Truncated {
		t.Errorf("exceeding the byte safety valve should mark truncated")
	}
	if result.Stdout != "12345678\n" {
		t.Errorf("body = %q", result.Stdout)
	}
}

// Stopping the source at a cap it was given is this tier's answer, whatever the
// stopped process reported on its way out: the killed writer's status is not a
// failure.
func TestHarvestCapStopIsTheAnswer(t *testing.T) {
	t.Parallel()
	src := fakeSourceCapped(8, []fakeChunk{line("12345678\n"), line("x\n")})
	result := harvestFor(t, src, 2*time.Second, model.RowCap{})
	if result.Verdict != model.VerdictAnswered {
		t.Fatalf("a deliberate stop should read as answered, got %+v", result)
	}
}

func TestHarvestDeadlineKeepsPartialOutput(t *testing.T) {
	t.Parallel()
	result := harvestFor(t, newStreamingSource(), 30*time.Millisecond, model.RowCap{})
	if result.Verdict != model.VerdictTimedOut {
		t.Fatalf("should end as a timeout: %+v", result)
	}
	if !strings.Contains(result.Stdout, "row\n") {
		t.Fatalf("a timeout should keep output already produced: %q", result.Stdout)
	}
}

func TestHarvestCancelKeepsPartialOutput(t *testing.T) {
	t.Parallel()
	src := newStreamingSource()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	result := harvest(ctx, src, model.RowCap{}, quickPace())
	cancel()
	if result.Verdict != model.VerdictInterrupted {
		t.Fatalf("should end as interrupted: %+v", result)
	}
	if !strings.Contains(result.Stdout, "row\n") {
		t.Fatalf("a cancel should keep output already produced: %q", result.Stdout)
	}
}

// A source that ignores stop entirely: the grace period expires, the output read
// before the stop is kept, and the result says the source would not stop — the
// output that never arrived is missing from the evidence, and a silent gap is
// the one thing a report must not have.
func TestHarvestGraceExpiryKeepsReadOutput(t *testing.T) {
	t.Parallel()
	src := newStuckSource()
	t.Cleanup(func() { close(src.release) })
	result := harvestFor(t, src, 30*time.Millisecond, model.RowCap{})
	if result.Verdict != model.VerdictTimedOut {
		t.Fatalf("should end as a timeout: %+v", result)
	}
	if !strings.Contains(result.Stdout, "early\n") {
		t.Fatalf("output read before the stop should be kept: %q", result.Stdout)
	}
	if !strings.Contains(result.Stderr, "did not stop within") {
		t.Fatalf("a source that would not stop should be reported: %q", result.Stderr)
	}
}

// A panic inside a harvest goroutine has no recover above it — it would end the
// process and lose the report — so the barrier reports it instead: the body is
// marked truncated (a reader that died cannot have read everything) and the
// reason lands in the source's stderr.
func TestHarvestSurvivesAPanickingReader(t *testing.T) {
	t.Parallel()
	src := fakeSourceOf(line("a\n"), line("b\n"), line("c\n"))
	reads := 0
	src.read = func() (string, bool) {
		reads++
		if reads == 3 {
			panic("reader blew up")
		}
		return src.next()
	}
	result := harvestFor(t, src, 2*time.Second, model.RowCap{})
	if result.Stdout != "a\nb\n" {
		t.Fatalf("output read before the panic should be kept: %q", result.Stdout)
	}
	if !result.Truncated {
		t.Fatal("a dead reader means the body is not known to be complete")
	}
	if !strings.Contains(result.Stderr, "harvest stdout reader") || !strings.Contains(result.Stderr, "reader blew up") {
		t.Fatalf("the reason should reach the source's stderr: %q", result.Stderr)
	}

	// The waiter's close(done) is deferred outside the barrier too: a panicking
	// wait must not leave the caller waiting for a signal that never comes, and
	// the message must be recorded before the waiter wakes — the read below would
	// otherwise race the report and this assertion would flake.
	var once sync.Once
	hung := fakeSourceOf()
	hung.onWait = func() { once.Do(func() { panic("wait blew up") }) }
	waited := harvestFor(t, hung, time.Second, model.RowCap{})
	if !strings.Contains(waited.Stderr, "harvest wait") || !strings.Contains(waited.Stderr, "wait blew up") {
		t.Fatalf("a panicking wait should be reported, got %+v", waited)
	}
}

// verdictFor is the one place the exit codes are read: 127 with nothing on
// stdout is the missing-command answer the scripts self-guard with, an exit code
// of 0 or any output is the tier's answer, and anything else is a failure.
func TestVerdictForReadsTheExitCode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		exitCode int
		stdout   string
		want     model.Verdict
	}{
		{"a clean exit", 0, "", model.VerdictAnswered},
		{"output with a non-zero exit", 1, "rows\n", model.VerdictAnswered},
		{"the shell's missing-command 127", 127, "", model.VerdictUnavailable},
		{"127 with output is an answer", 127, "rows\n", model.VerdictAnswered},
		{"a non-zero exit with nothing to show", 1, "  \n", model.VerdictFailed},
		{"a channel that could not say", -1, "", model.VerdictFailed},
	}
	for _, c := range cases {
		if got := verdictFor(c.exitCode, c.stdout); got != c.want {
			t.Errorf("%s: verdictFor(%d, %q) = %v, want %v", c.name, c.exitCode, c.stdout, got, c.want)
		}
	}
}

// cutVerdict is the one place a cut is named: the call's own deadline, or the
// operator's cancellation.
func TestCutVerdictReadsTheContext(t *testing.T) {
	t.Parallel()
	deadline, cancelDeadline := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancelDeadline()
	<-deadline.Done()
	if got := cutVerdict(deadline); got != model.VerdictTimedOut {
		t.Errorf("an expired deadline should read as a timeout, got %v", got)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if got := cutVerdict(cancelled); got != model.VerdictInterrupted {
		t.Errorf("a cancel should read as an interruption, got %v", got)
	}
}
