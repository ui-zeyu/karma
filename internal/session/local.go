// Local channel: turns an Invocation into a subprocess. The project's only
// subprocess spawn point. Command goes through exec without a shell; Shell goes
// through /bin/sh -c (rendering shared with SSH via shellcmd, POSIX only). A
// timeout kills the whole process tree; output already produced is kept.
package session

import (
	"bufio"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"karma/internal/model"
)

// LocalSession is the local channel.
type LocalSession struct{}

// LocalTransport is the local channel factory: the directory follows the host OS (the Windows directory on Windows).
type LocalTransport struct{}

// Name is the channel display name.
func (LocalTransport) Name() string { return "local" }

// Platform follows the host OS.
func (LocalTransport) Platform() model.Platform {
	if runtime.GOOS == "windows" {
		return model.Windows
	}
	return model.Linux
}

// Open: the local channel needs no connection.
func (LocalTransport) Open() (Session, error) { return LocalSession{}, nil }

// Name is the channel display name.
func (LocalSession) Name() string { return "local" }

// Target is the destination description.
func (LocalSession) Target() string { return "local" }

// Run sends the invocation to run locally.
func (s LocalSession) Run(inv model.Invocation, timeout time.Duration, lineLimit int) model.RunResult {
	return runLocal(ArgvFor(inv), timeout, lineLimit)
}

// Close: the local channel has no resources to release.
func (LocalSession) Close() error { return nil }

func runLocal(argv []string, timeout time.Duration, lineLimit int) model.RunResult {
	cmd := exec.Command(argv[0], argv[1:]...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return model.RunResult{Stderr: err.Error(), ExitCode: 127}
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return model.RunResult{Stderr: err.Error(), ExitCode: 127}
	}
	stop := prepareStop(cmd)
	if err := cmd.Start(); err != nil {
		// Capability probe passed but execution failed (binary just deleted, etc.): use 127 to follow fallback semantics
		return model.RunResult{Stderr: err.Error(), ExitCode: 127}
	}
	reader := bufio.NewReader(stdout)
	errReader := bufio.NewReader(stderrPipe)
	return harvestCapped(source{
		wait:     cmd.Wait,
		stop:     func() { stop(cmd.Process.Pid) },
		readLine: lineReader(reader),
		readAll: func() string {
			raw, _ := io.ReadAll(io.LimitReader(errReader, maxHarvestBytes))
			return validText(string(raw))
		},
		exitCode: func() int {
			if cmd.ProcessState == nil {
				return -1
			}
			return cmd.ProcessState.ExitCode()
		},
	}, timeout, lineLimit)
}

// validText replaces bad bytes with U+FFFD: stray output from the target must not blow up the whole check.
func validText(text string) string {
	return strings.ToValidUTF8(text, "\uFFFD")
}
