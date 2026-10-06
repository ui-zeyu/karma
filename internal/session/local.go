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
	"os"
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

// Describe names the channel in the report header: karma itself is the target,
// so the local host name is the whole description.
func (LocalSession) Describe() string { return "local" }

// Channel is which side of the wire karma runs on: karma itself is the target.
func (LocalSession) Channel() model.Channel { return model.ChanLocal }

// scriptOnly makes the local channel run every Dual tier's script side and skip
// the in-process body. It is read once, at startup, and exists for `make
// parity`: a Linux host collects twice — once in process, once through the
// scripts an ssh or ttyd target runs — and the two bundles are diffed check by
// check, which is the only way to see the two spellings drift.
var scriptOnly = os.Getenv("KARMA_NO_NATIVE") != ""

// Run sends the invocation to run locally. A Dual tier runs its in-process
// body first; everything else becomes a subprocess.
//
// A body that cannot answer on this host — it reads a kernel interface the
// host lacks, /proc on a non-Linux developer host — comes back unavailable, and
// the tier then runs its script side through the local shell. So the local
// channel answers wherever the ssh channel would, and the in-process body is
// what a Linux target uses.
func (s LocalSession) Run(ctx context.Context, inv model.Invocation, timeout time.Duration, cap model.RowCap) model.RunResult {
	if d, ok := inv.(model.Dual); ok {
		// A tier with no in-process body exists on the remote channels only, and
		// so does a body a parity run is asked to skip: both take the script side.
		if d.Run == nil || scriptOnly {
			if d.Script == "" {
				return model.RunResult{Verdict: model.VerdictUnavailable, Stderr: model.ErrTierUnavailable.Error(), ExitCode: 127}
			}
			return runLocal(ctx, posixShell(d.Script), timeout, cap)
		}
		result := runNative(ctx, d.Run, timeout, cap)
		// An unavailable body is the tier's own report that it cannot run here,
		// and it is the only verdict that sends the tier to its script side —
		// the same fall-through a missing binary takes on every other tier. A
		// Dual with no script side keeps the unavailable result, which is what
		// the runner's chain reads.
		if result.Verdict != model.VerdictUnavailable || d.Script == "" {
			return result
		}
		return runLocal(ctx, posixShell(d.Script), timeout, cap)
	}
	return runLocal(ctx, ArgvFor(inv), timeout, cap)
}

// Close releases the local channel's resources: there are none.
func (LocalSession) Close() error { return nil }

// localCall is one local subprocess as harvest's data source.
type localCall struct {
	baseSource
	cmd     *exec.Cmd
	stdout  *bufio.Reader
	stderr  *bufio.Reader
	process func(pid int)
}

func (c *localCall) wait()                    { _ = c.cmd.Wait() }
func (c *localCall) stop()                    { c.process(c.cmd.Process.Pid) }
func (c *localCall) readLine() (string, bool) { return readLineFrom(c.stdout) }
func (c *localCall) readAll() string          { return drainText(c.stderr) }

func (c *localCall) exitCode() int {
	if c.cmd.ProcessState == nil {
		return -1
	}
	return c.cmd.ProcessState.ExitCode()
}

func runLocal(ctx context.Context, argv []string, timeout time.Duration, cap model.RowCap) model.RunResult {
	cmd := exec.Command(argv[0], argv[1:]...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return model.RunResult{Verdict: model.VerdictFailed, Stderr: err.Error()}
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return model.RunResult{Verdict: model.VerdictFailed, Stderr: err.Error()}
	}
	process := prepareStop(cmd)
	if err := cmd.Start(); err != nil {
		// The capability probe passed and the exec still failed (the binary was
		// deleted in between): unavailable is the 127 a missing binary gives, so
		// the chain falls to the next tier.
		return model.RunResult{Verdict: model.VerdictUnavailable, Stderr: err.Error(), ExitCode: 127}
	}
	return harvest(ctx, &localCall{
		cmd:     cmd,
		stdout:  bufio.NewReader(stdout),
		stderr:  bufio.NewReader(stderrPipe),
		process: process,
	}, timeout, cap)
}

// validText replaces bad bytes with U+FFFD: stray output from the target must not blow up the whole check.
func validText(text string) string {
	return strings.ToValidUTF8(text, "\uFFFD")
}
