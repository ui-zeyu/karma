// SSHSession: one established SSH connection. Concurrent requests share the connection, each opening a channel.

package session

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"karma/internal/model"
	"karma/internal/script"
)

// SSHSession is one established SSH connection. agent is an optional ssh-agent
// connection; the signers also dial back during the handshake, so it is closed with the session.
type SSHSession struct {
	client *ssh.Client
	agent  io.Closer
	target string // the destination as the report header names it, empty in a bare test session
	lost   atomic.Bool
}

// Name is the channel display name.
func (s *SSHSession) Name() string { return "ssh" }

// Describe names the channel and the host it reached.
func (s *SSHSession) Describe() string {
	if s.target == "" {
		return "ssh"
	}
	return "ssh " + s.target
}

// Channel is which side of the wire karma runs on: the target is remote.
func (s *SSHSession) Channel() model.Channel { return model.ChanSSH }

// Lost reports whether the connection is gone — closed, or the server stopped
// answering. A channel the server refused leaves the connection alive and fails
// one tier instead, so a host that limits concurrent sessions does not end the
// run.
func (s *SSHSession) Lost() bool { return s.lost.Load() }

// Run sends the command string rendered through /bin/sh -c to the channel for execution.
func (s *SSHSession) Run(ctx context.Context, inv model.Invocation, timeout time.Duration, lineLimit int) model.RunResult {
	script := RenderShell(inv)
	sess, err := s.client.NewSession()
	if err != nil {
		if channelLost(err) {
			s.lost.Store(true)
		}
		return channelError(err)
	}
	defer sess.Close()
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return channelError(err)
	}
	stderrPipe, err := sess.StderrPipe()
	if err != nil {
		return channelError(err)
	}
	if err := sess.Start(script); err != nil {
		return channelError(err)
	}
	reader := bufio.NewReader(stdout)
	errReader := bufio.NewReader(stderrPipe)
	// Wait can be called only once: the wait goroutine stores the error and exitCode reads it from the cache.
	var waitErr error
	// The decoding strategy matches the local channel: line reads clean bad bytes, stderr switches to U+FFFD after draining.
	// stop closes the channel directly: a hung channel that never sees EOF is finished off by harvest's grace period.
	return harvestCapped(ctx, source{
		wait:     func() { waitErr = sess.Wait() },
		stop:     func() { _ = sess.Close() },
		readLine: lineReader(reader),
		readAll:  func() string { return drainText(errReader) },
		exitCode: func() int { return commandExitCode(waitErr) },
	}, timeout, lineLimit)
}

// Upload writes one file to the target: the content goes over the session's
// stdin, so the bootstrap mode ships a binary without a shell or a file
// transfer protocol in between. The remote side creates the file with the
// session's umask, before the bytes: a partial upload cannot be taken for a
// complete one.
func (s *SSHSession) Upload(ctx context.Context, path string, content []byte) error {
	sess, err := s.client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	cancelled := make(chan struct{})
	var stopWatch sync.Once
	defer stopWatch.Do(func() { close(cancelled) })
	go func() {
		select {
		case <-ctx.Done():
			_ = sess.Close()
		case <-cancelled:
		}
	}()
	var stalled atomic.Bool
	written := make(chan error, 1)
	go func() {
		err := writeUpload(stdin, content, &stalled, func() { _ = sess.Close() })
		// Closing the pipe is what tells the target's cat that the file is
		// complete: without it the remote side waits for more bytes.
		if closeErr := stdin.Close(); err == nil {
			err = closeErr
		}
		written <- err
	}()
	// umask first: the target's umask may leave the file world-readable, and
	// this one is a program the caller is about to exec — its own mode is set
	// once the bytes are in place, so a partial upload is never executable.
	// The directory comes with it, so the caller names a path and nothing else.
	command := script.Join([]string{"umask", "077"}) + "; " +
		script.Join([]string{"mkdir", "-p", filepath.Dir(path)}) + "; " +
		script.Join([]string{"cat"}) + " > " + script.Join([]string{path}) +
		" && " + script.Join([]string{"chmod", "700", path})
	if err := sess.Start(RenderShell(model.Shell{Script: command})); err != nil {
		return err
	}
	writeErr := <-written
	waitErr := sess.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if writeErr != nil {
		if stalled.Load() {
			return fmt.Errorf("no progress for %s: the target stopped reading", uploadStall)
		}
		return writeErr
	}
	if waitErr != nil {
		return fmt.Errorf("upload refused by the target: %w", waitErr)
	}
	return nil
}

// uploadChunk and uploadStall pace one upload: the ssh transport has no
// deadline of its own (the context the command line carries only sees SIGINT),
// so a target that stops draining the channel would block a Write forever. The
// idle timer is reset after every chunk, and the chunk is small enough that it
// measures a stop rather than a slow link.
const (
	uploadChunk = 64 << 10
)

// uploadStall is the idle bound; a variable so tests can shorten it.
var uploadStall = 60 * time.Second

// writeUpload writes one payload in chunks, arming abort when a chunk has not
// been handed over within uploadStall. stalled reports whether that happened,
// so the caller can name the reason.
func writeUpload(w io.Writer, content []byte, stalled *atomic.Bool, abort func()) error {
	timer := time.AfterFunc(uploadStall, func() {
		stalled.Store(true)
		abort()
	})
	defer timer.Stop()
	for offset := 0; offset < len(content); offset += uploadChunk {
		end := min(offset+uploadChunk, len(content))
		if _, err := w.Write(content[offset:end]); err != nil {
			return err
		}
		timer.Reset(uploadStall)
	}
	return nil
}

func channelError(err error) model.RunResult {
	return model.RunResult{Stderr: fmt.Sprintf("ssh channel error: %v", err), ExitCode: -1}
}

// channelLost reports whether a failed channel open means the connection itself
// is gone rather than this one channel being refused. The server's refusal comes
// back as its own typed answer (ssh.OpenChannelError: its session limit, a
// rejected request), which leaves the transport answering every later call — the
// refusal belongs to this tier alone. Everything else (a closed connection, a
// disconnect, an unanswered open) is the transport going away.
func channelLost(err error) bool {
	var refused *ssh.OpenChannelError
	return !errors.As(err, &refused)
}

// commandExitCode translates the ssh.Session.Wait error into an exit code. Wait
// returns nil when the remote exit code is 0; only non-zero is *ssh.ExitError.
// Errors with no exit status, such as a broken connection, are -1.
func commandExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exit *ssh.ExitError
	if errors.As(err, &exit) {
		return exit.ExitStatus()
	}
	return -1
}

// Close closes the connection. A hung Close does not wait past closeGrace, so the whole collection does not stall on teardown.
func (s *SSHSession) Close() error {
	done := make(chan struct{})
	go func() {
		_ = s.client.Close()
		close(done)
	}()
	timer := time.NewTimer(closeGrace)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
	if s.agent != nil {
		_ = s.agent.Close()
	}
	return nil
}
