// SSHSession: one established SSH connection. Concurrent requests share the connection, each opening a channel.

package session

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/ssh"

	"karma/internal/model"
)

// SSHSession is one established SSH connection. agent is an optional ssh-agent
// connection; the signers also dial back during the handshake, so it is closed with the session.
type SSHSession struct {
	client *ssh.Client
	agent  io.Closer
}

// Name is the channel display name.
func (s *SSHSession) Name() string { return "ssh" }

// Run sends the command string rendered through /bin/sh -c to the channel for execution.
func (s *SSHSession) Run(inv model.Invocation, timeout time.Duration, lineLimit int) model.RunResult {
	script := RenderShell(inv)
	sess, err := s.client.NewSession()
	if err != nil {
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
	return harvestCapped(source{
		wait:     func() { waitErr = sess.Wait() },
		stop:     func() { _ = sess.Close() },
		readLine: lineReader(reader),
		readAll:  func() string { return drainText(errReader) },
		exitCode: func() int { return commandExitCode(waitErr) },
	}, timeout, lineLimit)
}

func channelError(err error) model.RunResult {
	return model.RunResult{Stderr: fmt.Sprintf("ssh channel error: %v", err), ExitCode: -1}
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
