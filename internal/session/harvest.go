// Timeout harvesting: reads are attached first, the data source is stopped at
// the deadline, and output already produced is kept. A cancelled context
// (Ctrl-C) takes the same path as the timeout: stop the source, keep the
// partial output.
//
// The local subprocess, the SSH channel and the ttyd channel share this. The
// two read streams (stdout, stderr) each get their own goroutine: a timeout
// stops the data source, not the reads, so bytes already read are not lost.
// Reaping happens after the reads drain: Wait closes the read-side pipes and
// races with unread buffers (the os/exec StdoutPipe contract), so Wait returns
// immediately once everything is drained. The row cap's "stop once enough is
// read" also happens here: probe one extra line to confirm there is more
// content, then stop the source — that stop is this tier's answer — while the
// byte safety valve (maxHarvestBytes) stops the source at the limit and counts
// the body as truncated.
//
// One finished call is read into a model.Verdict here, the single place the
// exit codes are interpreted: every channel hands back this result and the
// chain above it reads the verdict alone.

package session

import (
	"bufio"
	"cmp"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
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
// byteLimit (the tests do).
const maxHarvestBytes = int64(64) << 20

// readLineFrom reads one line and cleans bad bytes: stray output from the
// target (GBK lines, binary leaking into stdout) is replaced with U+FFFD;
// stdout and stderr get the same treatment, so reading and rendering always see
// valid UTF-8.
func readLineFrom(reader *bufio.Reader) (string, bool) {
	line, err := reader.ReadString('\n')
	if line == "" && err != nil {
		return "", false
	}
	return validText(line), err == nil
}

// drainText reads the rest of one stream (stderr) and cleans bad bytes with the
// same U+FFFD policy as readLineFrom.
func drainText(reader *bufio.Reader) string {
	raw, _ := io.ReadAll(io.LimitReader(reader, maxHarvestBytes))
	return validText(string(raw))
}

// source is the data source of one call, implemented per channel: wait for the
// call to end, stop the data source (kill the process tree / close the
// channel), read one stdout line (ok=false is EOF), drain stderr, report the
// exit code (-1 when undetermined), and declare the byte valve.
type source interface {
	wait()
	stop()
	readLine() (string, bool)
	readAll() string
	exitCode() int
	byteLimit() int64
}

// baseSource carries what every channel's source shares beyond its own
// mechanics: the byte valve, which no production path tightens.
type baseSource struct{ limit int64 }

func (b baseSource) byteLimit() int64 { return b.limit }

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

// markPanicked records a harvest goroutine that panicked. The body is marked
// truncated because a reader that died mid-stream cannot have read everything,
// and the reason joins the source's stderr — the same place every other
// diagnostic of a call goes.
func (h *harvestState) markPanicked(reason string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.truncated = true
	h.errS.WriteString("harvest panic: " + reason + "\n")
}

func (h *harvestState) snapshot() (string, string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.out.String(), h.errS.String(), h.truncated
}

// harvest waits for the call to end, the timeout, or cancellation. On timeout
// or cancel it stops the source first and waits for exit within the grace
// period; both paths carry back the output read so far.
func harvest(ctx context.Context, src source, timeout time.Duration, cap model.RowCap) model.RunResult {
	// Each reader owns one builder through the locked state, so a snapshot is
	// safe at any point; the line-by-line path needs no extra ordering.
	var state harvestState

	// Once stopCh is closed, stdout reading stops: either the row cap, the byte
	// valve, the timeout, or the cancel triggered the stop. capped marks a stop
	// this harvest decided on: the source was stopped on purpose, so what it
	// produced is the tier's answer whatever the stopped process reports.
	stopCh := make(chan struct{})
	var (
		once   sync.Once
		capped atomic.Bool
	)
	stopSource := func(deliberate bool) {
		once.Do(func() {
			if deliberate {
				capped.Store(true)
			}
			close(stopCh)
			src.stop()
		})
	}

	var readers sync.WaitGroup
	readers.Add(2)
	byteLimit := cmp.Or(src.byteLimit(), maxHarvestBytes)
	go safeCall(func(problem error) { state.markPanicked(problem.Error()) }, readers.Done, func() {
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
			if cap.Rows > 0 && lines >= int64(cap.Rows) {
				// After enough rows, probe one more: stop the source if there is
				// more content; the extra line does not enter the body. A trailing
				// partial line has more=false but non-empty content and likewise
				// counts as "more content".
				if extra, _ := src.readLine(); extra != "" {
					state.markTruncated()
				}
				stopSource(true)
				return
			}
			// Byte safety valve: a runaway output can fill memory before the timeout, so stop at the limit
			if buffered >= byteLimit {
				state.markTruncated()
				stopSource(true)
				return
			}
		}
	})
	go safeCall(func(problem error) { state.markPanicked(problem.Error()) }, readers.Done, func() {
		state.addErr(src.readAll())
	})

	done := make(chan struct{})
	go safeCall(func(problem error) { state.markPanicked(problem.Error()) }, func() { close(done) }, func() {
		readers.Wait()
		src.wait()
	})

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
		exitCode := src.exitCode()
		outText, errText, trunc := state.snapshot()
		verdict := verdictFor(exitCode, outText)
		if capped.Load() {
			verdict = model.VerdictAnswered
		}
		return model.RunResult{Verdict: verdict, Stdout: outText, Stderr: errText, ExitCode: exitCode, Truncated: trunc}
	case <-deadline:
		return stopAndCollect(done, func() { stopSource(false) }, src, &state, false)
	case <-ctx.Done():
		return stopAndCollect(done, func() { stopSource(false) }, src, &state, true)
	}
}

// verdictFor reads one finished process the way every shell tier's chain does:
// 127 is the missing-command answer the scripts self-guard with (`command -v X
// || exit 127`), an exit code of 0 or any output on stdout is the tier's answer
// (an empty answer is an answer), and anything else is a failure whose stderr a
// panel names.
func verdictFor(exitCode int, stdout string) model.Verdict {
	switch {
	case exitCode == 127 && strings.TrimSpace(stdout) == "":
		return model.VerdictUnavailable
	case exitCode == 0 || strings.TrimSpace(stdout) != "":
		return model.VerdictAnswered
	}
	return model.VerdictFailed
}

// safeCall runs one goroutine of a call and signals its completion. A panic in a
// goroutine has no recover above it, so it would end the process and take the
// whole report with it, where the contract is that one broken check fails alone.
// report records the panic where the call's own result paths read it, and it
// runs in the same deferred call as finished, so a waiter is never woken before
// the panic is recorded. A helper with no result path of its own passes a no-op
// reporter: the recover still keeps the process alive, and the caller's own
// timeout or grace path ends the call.
func safeCall(report func(error), finished func(), run func()) {
	defer func() {
		if problem := recover(); problem != nil {
			report(fmt.Errorf("%v", problem))
		}
		finished()
	}()
	run()
}

// stopAndCollect stops the data source and keeps what was read: the reads drain
// within the grace period, or the snapshot lands on whatever arrived by then.
// interrupted selects between the timeout and the cancel verdict.
func stopAndCollect(done chan struct{}, stopSource func(), src source, state *harvestState, interrupted bool) model.RunResult {
	stopSource()
	grace := time.NewTimer(stopGrace)
	defer grace.Stop()
	select {
	case <-done:
	case <-grace.C:
	}
	verdict := model.VerdictTimedOut
	if interrupted {
		verdict = model.VerdictInterrupted
	}
	outText, errText, trunc := state.snapshot()
	return model.RunResult{
		Verdict: verdict, Stdout: outText, Stderr: errText, ExitCode: -1, Truncated: trunc,
	}
}
