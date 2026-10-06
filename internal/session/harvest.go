// Harvesting one call: reads are attached first, the data source is stopped when
// the call's deadline ends or the operator cancels, and output already produced
// is kept.
//
// The local subprocess, the SSH channel and the ttyd channel share this. The
// two read streams (stdout, stderr) each get their own goroutine: the deadline
// stops the data source, not the reads, so bytes already read are not lost.
// Reaping happens after the reads drain: Wait closes the read-side pipes and
// races with unread buffers (the os/exec StdoutPipe contract), so Wait returns
// immediately once everything is drained. The row cap's "stop once enough is
// read" also happens here: probe one extra line to confirm there is more
// content, then stop the source — that stop is this tier's answer — while the
// byte safety valve (maxHarvestBytes) stops the source at the limit and counts
// the body as truncated.
//
// The deadline is the context's, so the one number an operator gave bounds the
// channel's setup too. One finished call is read into a model.Verdict here, the
// single place the exit codes are interpreted and the single place a cut is
// named: every channel hands back this result and the chain above it reads the
// verdict alone.

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

	"karma/internal/fault"
	"karma/internal/model"
)

// cutGrace is how long a stopped source has to finish before the harvest gives
// up on it and keeps what the reads already had. Every channel's stop releases
// its reads at once — the local one SIGKILLs the process group, the ssh one
// closes the channel, ttyd closes the connection — so a source that outlives
// this is a source that cannot be stopped, and the result then says so. A
// variable so tests can shorten it.
var cutGrace = time.Second

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
// deadline and cancel paths can snapshot mid-read: even a source that survives
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

// markDamaged records a harvest goroutine that panicked. The body is marked
// truncated because a reader that died mid-stream cannot have read everything,
// and the reason joins the source's stderr — the same place every other
// diagnostic of a call goes.
func (h *harvestState) markDamaged(problem error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.truncated = true
	h.errS.WriteString(problem.Error() + "\n")
}

func (h *harvestState) snapshot() (string, string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.out.String(), h.errS.String(), h.truncated
}

// harvest waits for the call to end or for the context to end it. On a cut it
// stops the source first and waits for it within the grace period; both paths
// carry back the output read so far.
func harvest(ctx context.Context, src source, cap model.RowCap) model.RunResult {
	// Each reader owns one builder through the locked state, so a snapshot is
	// safe at any point; the line-by-line path needs no extra ordering.
	var state harvestState

	// Once stopCh is closed, stdout reading stops: either the row cap, the byte
	// valve, the deadline, or the cancel triggered the stop. capped marks a stop
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
	// The panic barrier records a broken reader before it signals completion: a
	// waiter woken first would read the state as if the reader had ended
	// normally.
	go func() {
		defer readers.Done()
		err := fault.Catch("harvest stdout reader", func() error {
			readStdout(src, stopCh, &state, cap, byteLimit, stopSource)
			return nil
		})
		if err != nil {
			state.markDamaged(err)
		}
	}()
	go func() {
		defer readers.Done()
		if err := fault.Catch("harvest stderr reader", func() error {
			state.addErr(src.readAll())
			return nil
		}); err != nil {
			state.markDamaged(err)
		}
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := fault.Catch("harvest wait", func() error {
			readers.Wait()
			src.wait()
			return nil
		}); err != nil {
			state.markDamaged(err)
		}
	}()

	select {
	case <-done:
		exitCode := src.exitCode()
		outText, errText, trunc := state.snapshot()
		verdict := verdictFor(exitCode, outText)
		if capped.Load() {
			verdict = model.VerdictAnswered
		}
		return model.RunResult{Verdict: verdict, Stdout: outText, Stderr: errText, ExitCode: exitCode, Truncated: trunc}
	case <-ctx.Done():
		return stopAndCollect(done, func() { stopSource(false) }, src, &state, ctx)
	}
}

// readStdout is the stdout reader: it collects lines into the state and decides
// the two deliberate stops. The row cap probes one line past the limit to learn
// whether there is more, and the byte valve stops a runaway body before memory
// fills; both are this tier's answer, so they stop the source "deliberately"
// rather than as a cut.
func readStdout(src source, stopCh <-chan struct{}, state *harvestState, cap model.RowCap, byteLimit int64, stop func(deliberate bool)) {
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
			// A trailing partial line has more=false but non-empty content and
			// likewise counts as "more content"; the extra line does not enter
			// the body.
			if extra, _ := src.readLine(); extra != "" {
				state.markTruncated()
			}
			stop(true)
			return
		}
		if buffered >= byteLimit {
			state.markTruncated()
			stop(true)
			return
		}
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

// cutVerdict names why a wait ended: the call's own deadline, or the operator's
// cancellation. Every cut reads it here, so the two are one rule rather than
// one branch per channel.
func cutVerdict(ctx context.Context) model.Verdict {
	if ctx.Err() == context.DeadlineExceeded {
		return model.VerdictTimedOut
	}
	return model.VerdictInterrupted
}

// stopAndCollect stops the data source and keeps what was read: the reads drain
// within the grace period, or the snapshot lands on whatever arrived by then. A
// source that outlives the grace is a source that could not be stopped, and the
// result says so — the output that never arrived is missing from the evidence,
// and a silent gap is the one thing a report must not have.
func stopAndCollect(done <-chan struct{}, stopSource func(), src source, state *harvestState, ctx context.Context) model.RunResult {
	stopSource()
	grace := time.NewTimer(cutGrace)
	defer grace.Stop()
	stopped := false
	select {
	case <-done:
		stopped = true
	case <-grace.C:
	}
	outText, errText, trunc := state.snapshot()
	if !stopped {
		errText += fmt.Sprintf("the call did not stop within %s: this is the output that arrived\n", cutGrace)
		trunc = true
	}
	return model.RunResult{
		Verdict: cutVerdict(ctx), Stdout: outText, Stderr: errText, ExitCode: -1, Truncated: trunc,
	}
}
