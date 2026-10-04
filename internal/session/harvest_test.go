package session

import (
	"testing"
	"time"
)

// fakeChunk is one readLine response: ok=false with non-empty text is a trailing partial line without a newline.
type fakeChunk struct {
	text string
	ok   bool
}

func fakeSource(chunks []fakeChunk) source {
	index := 0
	return source{
		wait: func() error { return nil },
		stop: func() {},
		readLine: func() (string, bool) {
			if index >= len(chunks) {
				return "", false
			}
			chunk := chunks[index]
			index++
			return chunk.text, chunk.ok
		},
		readAll:  func() string { return "" },
		exitCode: func() int { return 0 },
	}
}

func line(text string) fakeChunk { return fakeChunk{text: text, ok: true} }
func tail(text string) fakeChunk { return fakeChunk{text: text, ok: false} } // last line without a newline

func TestHarvestLineLimitCleanEOF(t *testing.T) {
	src := fakeSource([]fakeChunk{line("a\n"), line("b\n"), line("c\n")})
	result := harvest(src, 2*time.Second, 3)
	if result.Truncated {
		t.Errorf("EOF exactly at the limit does not count as truncated")
	}
	if result.Stdout != "a\nb\nc\n" {
		t.Errorf("body = %q", result.Stdout)
	}
}

func TestHarvestLineLimitTruncated(t *testing.T) {
	src := fakeSource([]fakeChunk{line("a\n"), line("b\n"), line("c\n"), line("d\n")})
	result := harvest(src, 2*time.Second, 3)
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
	result := harvest(src, 2*time.Second, 3)
	if !result.Truncated {
		t.Errorf("a trailing partial line after the limit should mark truncated")
	}
	if result.Stdout != "a\nb\nc\n" {
		t.Errorf("body = %q", result.Stdout)
	}
}

func TestHarvestByteCap(t *testing.T) {
	original := maxHarvestBytes
	maxHarvestBytes = 8
	defer func() { maxHarvestBytes = original }()

	src := fakeSource([]fakeChunk{line("12345678\n"), line("x\n")})
	result := harvest(src, 2*time.Second, 0)
	if !result.Truncated {
		t.Errorf("exceeding the byte safety valve should mark truncated")
	}
	if result.Stdout != "12345678\n" {
		t.Errorf("body = %q", result.Stdout)
	}
}
