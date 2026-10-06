//go:build unix

package cli

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The first interrupt cancels the run's context: collection stops, in-flight
// checks keep what they read, and the report is still presented.
func TestInterruptibleCancelsOnTheFirstSignal(t *testing.T) {
	ctx, stop := interruptible()
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("send SIGINT: %v", err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("a signal should cancel the run's context")
	}
}

// The cleanup takes the handler away again, so a signal after the run is over
// keeps its default meaning: the process must not be left swallowing signals it
// no longer acts on.
func TestInterruptibleCleanupStopsTheHandler(t *testing.T) {
	ctx, stop := interruptible()
	stop()
	stop() // idempotent: Main defers it, a command may already have ended it
	<-ctx.Done()
}

// The escalation, checked on a real process: the second interrupt exits at once
// with the interrupted status, which is the only way out of a channel operation
// the context cannot break. The child says it is ready before the parent signals,
// so the first signal cannot arrive before the handler is installed.
func TestSecondSignalExitsAtOnce(t *testing.T) {
	if os.Getenv("KARMA_SECOND_SIGNAL_CHILD") != "" {
		ctx, stop := interruptible()
		defer stop()
		fmt.Println("ready")
		<-ctx.Done()
		select {} // the second signal is what ends this process
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestSecondSignalExitsAtOnce")
	cmd.Env = append(os.Environ(), "KARMA_SECOND_SIGNAL_CHILD=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the child: %v", err)
	}
	// A child that never exits would hang the test: kill it instead.
	guard := time.AfterFunc(20*time.Second, func() { _ = cmd.Process.Kill() })
	defer guard.Stop()
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatalf("the child should have installed its handler: %q, %v", line, err)
	}
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("first signal: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("second signal: %v", err)
	}
	err = cmd.Wait()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("the child should have exited on the second signal, got %v (stderr: %s)", err, stderr.String())
	}
	if exit.ExitCode() != int(ExitInterrupted) {
		t.Fatalf("a second interrupt exits at once with %d, got %d", ExitInterrupted, exit.ExitCode())
	}
	if !strings.Contains(stderr.String(), "again, exiting now") {
		t.Fatalf("the escalation should be said out loud: %q", stderr.String())
	}
}
