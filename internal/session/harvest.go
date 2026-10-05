// Timeout harvesting: reads are attached first, the data source is stopped at
// the deadline, and output already produced is kept. A cancelled context
// (Ctrl-C) takes the same path as the timeout: stop the source, keep the
// partial output.
//
// The local subprocess and the SSH channel share this. The two read streams
// (stdout, stderr) each get their own goroutine: a timeout stops the data
// source, not the reads, so bytes already read are not lost. Reaping happens
// after the reads drain: Wait closes the read-side pipes and races with unread
// buffers (the os/exec StdoutPipe contract), so Wait returns immediately once
// everything is drained. The line limit's "stop once enough is read" also
// happens here: probe one extra line to confirm there is more content, then
// stop the source and count the body as this tier's answer; the byte safety
// valve (maxHarvestBytes) likewise stops the source at the limit and counts as
// truncated.

package session

import (
	"bufio"
	"cmp"
	"context"
	"io"
	"strings"
	"sync"
	"time"

	"karma/internal/model"
)

// stopGrace is the grace period to finish after stopping the data source; if the
// source cannot be stopped (a hung channel), it ends as a timeout or cancel and
// the output read so far is kept. A variable so tests can shorten it.
var stopGrace = 5 * time.Second

// maxHarvestBytes is the output safety valve for a single call: past the limit,
// stop the source and count as truncated. The reading layer caps by ScanBytes
// anyway, so collecting more is pointless. A source can tighten it through
// source.byteLimit (the tests do).
const maxHarvestBytes = int64(64) << 20

// lineReader reads line by line and cleans bad bytes: stray output from the
// target (GBK lines, binary leaking into stdout) is replaced with U+FFFD;
// stdout and stderr get the same treatment, so reading and rendering always see
// valid UTF-8.
func lineReader(reader *bufio.Reader) func() (string, bool) {
	return func() (string, bool) {
		line, err := reader.ReadString('\n')
		if line == "" && err != nil {
			return "", false
		}
		return validText(line), err == nil
	}
}

// drainText reads the rest of one stream (stderr) and cleans bad bytes with the
// same U+FFFD policy as lineReader.
func drainText(reader *bufio.Reader) string {
	raw, _ := io.ReadAll(io.LimitReader(reader, maxHarvestBytes))
	return validText(string(raw))
}

// source is the data source of one call, provided by the channel implementation.
// wait waits for the call to end; stop stops the data source (kill the process
// tree / close the channel); readLine reads one stdout line (ok=false is EOF);
// readAll drains stderr; exitCode returns the exit code (-1 when undetermined);
// byteLimit overrides maxHarvestBytes when positive.
type source struct {
	wait      func()
	stop      func()
	readLine  func() (string, bool)
	readAll   func() string
	exitCode  func() int
	byteLimit int64
}

// harvestState buffers the two read streams. Every write takes the lock so the
// timeout and cancel paths can snapshot mid-read: even a source that survives
// stop past the grace period keeps what it already produced.
type harvestState struct {
	mu        sync.Mutex
	out, errS strings.Builder
	truncated bool
}

func (h *harvestState) addOut(chunk string) {
	if chunk == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.out.WriteString(chunk)
}

func (h *harvestState) addErr(text string) {
	if text == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.errS.WriteString(text)
}

func (h *harvestState) markTruncated() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.truncated = true
}

func (h *harvestState) snapshot() (string, string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.out.String(), h.errS.String(), h.truncated
}

// harvest waits for the call to end, the timeout, or cancellation. On timeout
// or cancel it stops the source first and waits for exit within the grace
// period; both paths carry back the output read so far.
func harvest(ctx context.Context, src source, timeout time.Duration, lineLimit int) model.RunResult {
	// Each reader owns one builder through the locked state, so a snapshot is
	// safe at any point; the line-by-line path needs no extra ordering.
	var state harvestState

	// Once stopCh is closed, stdout reading stops: either the line limit, the
	// timeout, or the cancel triggered the stop.
	stopCh := make(chan struct{})
	var once sync.Once
	stopSource := func() {
		once.Do(func() {
			close(stopCh)
			src.stop()
		})
	}

	var readers sync.WaitGroup
	readers.Add(2)
	byteLimit := cmp.Or(src.byteLimit, maxHarvestBytes)
	go func() {
		defer readers.Done()
		var lines, buffered int64
		for {
			select {
			case <-stopCh:
				return
			default:
			}
			chunk, ok := src.readLine()
			state.addOut(chunk)
			if chunk != "" {
				lines++
				buffered += int64(len(chunk))
			}
			if !ok {
				return
			}
			if lineLimit > 0 && lines >= int64(lineLimit) {
				// After enough lines, probe one more: stop the source if there is
				// more content; the extra line does not enter the body. A trailing
				// partial line has more=false but non-empty content and likewise
				// counts as "more content".
				if extra, _ := src.readLine(); extra != "" {
					state.markTruncated()
				}
				stopSource()
				return
			}
			// Byte safety valve: a runaway output can fill memory before the timeout, so stop at the limit
			if buffered >= byteLimit {
				state.markTruncated()
				stopSource()
				return
			}
		}
	}()
	go func() {
		defer readers.Done()
		state.addErr(src.readAll())
	}()

	done := make(chan struct{})
	go func() {
		readers.Wait()
		src.wait()
		close(done)
	}()

	// A timeout of zero or less is no deadline, the same reading the in-process
	// tier gives it: only the context then ends the call.
	var deadline <-chan time.Time
	if timeout > 0 {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		deadline = timer.C
	}
	select {
	case <-done:
		outText, errText, trunc := state.snapshot()
		return model.RunResult{Stdout: outText, Stderr: errText, ExitCode: src.exitCode(), Truncated: trunc}
	case <-deadline:
		return stopAndCollect(done, stopSource, src, &state, false)
	case <-ctx.Done():
		return stopAndCollect(done, stopSource, src, &state, true)
	}
}

// stopAndCollect stops the data source and keeps what was read: the reads drain
// within the grace period, or the snapshot lands on whatever arrived by then.
// interrupted selects between the timeout and the cancel presentation.
func stopAndCollect(done chan struct{}, stopSource func(), src source, state *harvestState, interrupted bool) model.RunResult {
	stopSource()
	grace := time.NewTimer(stopGrace)
	defer grace.Stop()
	select {
	case <-done:
	case <-grace.C:
	}
	outText, errText, trunc := state.snapshot()
	return model.RunResult{
		Stdout: outText, Stderr: errText, ExitCode: -1,
		TimedOut: !interrupted, Interrupted: interrupted, Truncated: trunc,
	}
}

// harvestCapped is one call with a line limit: stopping the data source after
// limit lines counts the body as success.
//
// The body from stopping at enough lines is already this tier's answer (fallback
// semantics), so the exit code is reported as 0 with the truncated flag (the
// frame marks "truncated" from it); a timeout is still presented as a timeout.
// limit 0 means no cap.
func harvestCapped(ctx context.Context, src source, timeout time.Duration, limit int) model.RunResult {
	result := harvest(ctx, src, timeout, limit)
	if result.Truncated && !result.TimedOut && !result.Interrupted {
		result.ExitCode = 0
	}
	return result
}
