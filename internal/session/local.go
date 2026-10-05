// Local channel: turns an Invocation into a subprocess, or runs a Dual tier's
// in-process body itself. This is the channel's spawn point; the in-process
// tiers ask a host binary through their own runner (native.runHost), and
// Windows stops a process tree with taskkill. Command goes through exec
// without a shell; Shell goes through /bin/sh -c (rendering shared with SSH via
// shellcmd, POSIX only). A timeout kills the whole process tree; output already
// produced is kept.

package session

import (
	"bufio"
	"context"
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

// Platform follows the host OS.
func (LocalTransport) Platform() model.Platform {
	if runtime.GOOS == "windows" {
		return model.Windows
	}
	return model.Linux
}

// Open is the local channel's connection step: there is nothing to connect.
func (LocalTransport) Open() (Session, error) { return LocalSession{}, nil }

// Name is the channel display name.
func (LocalSession) Name() string { return "local" }

// Channel is which side of the wire karma runs on: karma itself is the target.
func (LocalSession) Channel() model.Channel { return model.ChanLocal }

// Run sends the invocation to run locally. A Dual tier runs its in-process
// body first; everything else becomes a subprocess.
//
// A body that cannot answer on this host — it reads a kernel interface the
// host lacks, /proc on a non-Linux developer host — reports
// model.ErrTierUnavailable, and the tier then runs its script side through the
// local shell. So the local channel answers wherever the ssh channel would,
// and the in-process body is what a Linux target uses.
func (s LocalSession) Run(ctx context.Context, inv model.Invocation, timeout time.Duration, lineLimit int) model.RunResult {
	if d, ok := inv.(model.Dual); ok {
		// Exit 127 is runNative's mapping of ErrTierUnavailable, the same code
		// a missing binary yields; it is the only 127 a body can produce.
		if result := runNative(ctx, d.Run, timeout, lineLimit); result.ExitCode != 127 || d.Script == "" {
			return result
		}
		return runLocal(ctx, posixShell(d.Script), timeout, lineLimit)
	}
	return runLocal(ctx, ArgvFor(inv), timeout, lineLimit)
}

// Close releases the local channel's resources: there are none.
func (LocalSession) Close() error { return nil }

func runLocal(ctx context.Context, argv []string, timeout time.Duration, lineLimit int) model.RunResult {
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
	return harvestCapped(ctx, source{
		wait:     func() { _ = cmd.Wait() },
		stop:     func() { stop(cmd.Process.Pid) },
		readLine: lineReader(reader),
		readAll:  func() string { return drainText(errReader) },
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
