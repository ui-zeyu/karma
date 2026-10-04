// Timeout harvesting: reads are attached first, the data source is stopped at
// the deadline, and output already produced is kept.
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
	"io"
	"strings"
	"sync"
	"time"

	"karma/internal/model"
)

// stopGrace is the grace period to finish after stopping the data source; if the
// source cannot be stopped (a hung channel), it ends as a timeout and read output is discarded.
const stopGrace = 5 * time.Second

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

// harvest waits for the call to end or the timeout. On timeout it stops first and
// waits for exit within the grace period; both paths carry back the output read
// so far; if it still cannot stop within the grace period it ends as a timeout and discards the read output.
func harvest(src source, timeout time.Duration, lineLimit int) model.RunResult {
	// Each reader owns one builder, and every snapshot happens only after done
	// closes (reads drained, source reaped): the channel close orders all of it, so
	// the line-by-line path needs no lock.
	var (
		out, errS strings.Builder
		truncated bool
	)
	snapshot := func() (string, string, bool) {
		return out.String(), errS.String(), truncated
	}

	// Once stopCh is closed, stdout reading stops: either the line limit or the timeout triggered the stop.
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
			if chunk != "" {
				out.WriteString(chunk)
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
					truncated = true
				}
				stopSource()
				return
			}
			// Byte safety valve: a runaway output can fill memory before the timeout, so stop at the limit
			if buffered >= byteLimit {
				truncated = true
				stopSource()
				return
			}
		}
	}()
	go func() {
		defer readers.Done()
		errS.WriteString(src.readAll())
	}()

	done := make(chan struct{})
	go func() {
		readers.Wait()
		src.wait()
		close(done)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		outText, errText, trunc := snapshot()
		return model.RunResult{Stdout: outText, Stderr: errText, ExitCode: src.exitCode(), Truncated: trunc}
	case <-timer.C:
		stopSource()
		grace := time.NewTimer(stopGrace)
		defer grace.Stop()
		select {
		case <-done:
			// A kill-stop has no exit code; output already produced is kept
			outText, errText, _ := snapshot()
			return model.RunResult{Stdout: outText, Stderr: errText, ExitCode: -1, TimedOut: true}
		case <-grace.C:
			return model.RunResult{Stdout: "", Stderr: "", ExitCode: -1, TimedOut: true}
		}
	}
}

// harvestCapped is one call with a line limit: stopping the data source after
// limit lines counts the body as success.
//
// The body from stopping at enough lines is already this tier's answer (fallback
// semantics), so the exit code is reported as 0 with the truncated flag (the
// frame marks "truncated" from it); a timeout is still presented as a timeout.
// limit 0 means no cap.
func harvestCapped(src source, timeout time.Duration, limit int) model.RunResult {
	result := harvest(src, timeout, limit)
	if result.Truncated && !result.TimedOut {
		result.ExitCode = 0
	}
	return result
}
