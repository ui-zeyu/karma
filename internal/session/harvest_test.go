package session

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeChunk is one readLine response: ok=false with non-empty text is a trailing partial line without a newline.
type fakeChunk struct {
	text string
	ok   bool
}

func fakeSource(chunks []fakeChunk) source {
	return fakeSourceCapped(0, chunks)
}

// fakeSourceCapped is a source with the byte safety valve tightened, so the cap
// is reachable in a test.
func fakeSourceCapped(byteLimit int64, chunks []fakeChunk) source {
	index := 0
	return source{
		wait: func() {},
		stop: func() {},
		readLine: func() (string, bool) {
			if index >= len(chunks) {
				return "", false
			}
			chunk := chunks[index]
			index++
			return chunk.text, chunk.ok
		},
		readAll:   func() string { return "" },
		exitCode:  func() int { return 0 },
		byteLimit: byteLimit,
	}
}

func line(text string) fakeChunk { return fakeChunk{text: text, ok: true} }
func tail(text string) fakeChunk { return fakeChunk{text: text, ok: false} } // last line without a newline

// streamingSource produces lines until stopped and keeps readLine hanging after
// the stop, so both stop paths run through the grace period. Callers shorten
// stopGrace with shortGrace.
func streamingSource() source {
	stopped := make(chan struct{})
	var once sync.Once
	return source{
		wait: func() {},
		stop: func() { once.Do(func() { close(stopped) }) },
		readLine: func() (string, bool) {
			select {
			case <-stopped:
				<-make(chan struct{}) // a pathological source: reads hang past the stop
				return "", false
			default:
			}
			return "row\n", true
		},
		readAll:  func() string { return "" },
		exitCode: func() int { return -1 },
	}
}

// shortGrace shortens the grace period for the duration of one test: the real
// 5s would turn every hung-source test into a slow one.
func shortGrace(t *testing.T) {
	t.Helper()
	original := stopGrace
	stopGrace = 50 * time.Millisecond
	t.Cleanup(func() { stopGrace = original })
}

func TestHarvestLineLimitCleanEOF(t *testing.T) {
	src := fakeSource([]fakeChunk{line("a\n"), line("b\n"), line("c\n")})
	result := harvest(context.Background(), src, 2*time.Second, 3)
	if result.Truncated {
		t.Errorf("EOF exactly at the limit does not count as truncated")
	}
	if result.Stdout != "a\nb\nc\n" {
		t.Errorf("body = %q", result.Stdout)
	}
}

func TestHarvestLineLimitTruncated(t *testing.T) {
	src := fakeSource([]fakeChunk{line("a\n"), line("b\n"), line("c\n"), line("d\n")})
	result := harvest(context.Background(), src, 2*time.Second, 3)
	if !result.Truncated {
		t.Errorf("a complete line after the limit should mark truncated")
	}
	if result.Stdout != "a\nb\nc\n" {
		t.Errorf("body = %q", result.Stdout)
	}
}

// A trailing partial line has more=false but non-empty content: the truncated flag was once missed because the condition included more.
func TestHarvestLineLimitPartialTail(t *testing.T) {
	src := fakeSource([]fakeChunk{line("a\n"), line("b\n"), line("c\n"), tail("partial")})
	result := harvest(context.Background(), src, 2*time.Second, 3)
	if !result.Truncated {
		t.Errorf("a trailing partial line after the limit should mark truncated")
	}
	if result.Stdout != "a\nb\nc\n" {
		t.Errorf("body = %q", result.Stdout)
	}
}

func TestHarvestByteCap(t *testing.T) {
	src := fakeSourceCapped(8, []fakeChunk{line("12345678\n"), line("x\n")})
	result := harvest(context.Background(), src, 2*time.Second, 0)
	if !result.Truncated {
		t.Errorf("exceeding the byte safety valve should mark truncated")
	}
	if result.Stdout != "12345678\n" {
		t.Errorf("body = %q", result.Stdout)
	}
}

func TestHarvestTimeoutKeepsPartialOutput(t *testing.T) {
	shortGrace(t)
	result := harvest(context.Background(), streamingSource(), 30*time.Millisecond, 0)
	if !result.TimedOut || result.Interrupted {
		t.Fatalf("should end as a timeout: %+v", result)
	}
	if !strings.Contains(result.Stdout, "row\n") {
		t.Fatalf("a timeout should keep output already produced: %q", result.Stdout)
	}
}

func TestHarvestCancelKeepsPartialOutput(t *testing.T) {
	shortGrace(t)
	src := streamingSource()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	result := harvest(ctx, src, time.Minute, 0)
	cancel()
	if !result.Interrupted || result.TimedOut {
		t.Fatalf("should end as interrupted: %+v", result)
	}
	if !strings.Contains(result.Stdout, "row\n") {
		t.Fatalf("a cancel should keep output already produced: %q", result.Stdout)
	}
}

// A source that ignores stop entirely: the grace period expires and the output
// read before the stop is still kept instead of discarded.
func TestHarvestGraceExpiryKeepsReadOutput(t *testing.T) {
	shortGrace(t)
	unstoppable := make(chan struct{})
	src := source{
		wait: func() {},
		stop: func() { close(unstoppable) },
		readLine: func() (string, bool) {
			select {
			case <-unstoppable:
				<-make(chan struct{}) // hangs forever, stop or no stop
				return "", false
			default:
			}
			return "early\n", true
		},
		readAll:  func() string { return "" },
		exitCode: func() int { return -1 },
	}
	result := harvest(context.Background(), src, 30*time.Millisecond, 0)
	if !result.TimedOut {
		t.Fatalf("should end as a timeout: %+v", result)
	}
	if !strings.Contains(result.Stdout, "early\n") {
		t.Fatalf("output read before the stop should be kept: %q", result.Stdout)
	}
}

// A panic inside a harvest goroutine has no recover above it — it would end the
// process and lose the report — so the barrier reports it instead: the body is
// marked truncated (a reader that died cannot have read everything) and the
// reason lands in the source's stderr.
func TestHarvestSurvivesAPanickingReader(t *testing.T) {
	chunks := []fakeChunk{line("a\n"), line("b\n"), line("c\n")}
	src := fakeSource(chunks)
	readLine := src.readLine
	reads := 0
	src.readLine = func() (string, bool) {
		reads++
		if reads == 3 {
			panic("reader blew up")
		}
		return readLine()
	}
	result := harvest(context.Background(), src, 2*time.Second, 0)
	if result.Stdout != "a\nb\n" {
		t.Fatalf("output read before the panic should be kept: %q", result.Stdout)
	}
	if !result.Truncated {
		t.Fatal("a dead reader means the body is not known to be complete")
	}
	if !strings.Contains(result.Stderr, "harvest panic: reader blew up") {
		t.Fatalf("the reason should reach the source's stderr: %q", result.Stderr)
	}

	// The waiter's close(done) is deferred inside the barrier too: a panicking
	// wait must not leave the caller waiting for a signal that never comes.
	var once sync.Once
	hung := fakeSource(nil)
	hung.wait = func() { once.Do(func() { panic("wait blew up") }) }
	waited := harvest(context.Background(), hung, time.Second, 0)
	if !strings.Contains(waited.Stderr, "harvest panic: wait blew up") {
		t.Fatalf("a panicking wait should be reported, got %+v", waited)
	}
}
