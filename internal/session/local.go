// Local channel: turns an Invocation into a subprocess, or runs a Dual tier's
// in-process body itself. This is the channel's spawn point; the in-process
// tiers ask a host binary through their own runner (native.runHost), and
// Windows stops a process tree with taskkill. Command goes through exec
// without a shell; Shell goes through /bin/sh -c (rendering shared with SSH via
// shellcmd, POSIX only). The call's deadline kills the whole process tree;
// output already produced is kept.

package session

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"

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
func (LocalTransport) Open(context.Context) (Session, error) { return LocalSession{}, nil }

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
var scriptOnly = envSwitch("KARMA_NO_NATIVE")

// envSwitch reads a boolean environment switch: unset, "0", "false" and "no"
// are off and any other value is on, so `KARMA_NO_NATIVE=0` leaves the
// in-process tiers in place — the value a script that wants them writes.
func envSwitch(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "", "0", "false", "no":
		return false
	}
	return true
}

// Run sends the invocation to run locally. A Dual tier runs its in-process
// body first; everything else becomes a subprocess.
//
// A body that cannot answer on this host — it reads a kernel interface the
// host lacks, /proc on a non-Linux developer host — comes back unavailable, and
// the tier then runs its script side through the local shell. So the local
// channel answers wherever the ssh channel would, and the in-process body is
// what a Linux target uses.
func (s LocalSession) Run(ctx context.Context, call model.Call) model.RunResult {
	if d, ok := call.Inv.(model.Dual); ok {
		// A tier with no in-process body exists on the remote channels only, and
		// so does a body a parity run is asked to skip: both take the script side.
		if d.Run == nil || scriptOnly {
			if d.Script == "" {
				return model.RunResult{Verdict: model.VerdictUnavailable, Stderr: model.ErrTierUnavailable.Error(), ExitCode: 127}
			}
			return runLocal(ctx, posixShell(d.Script), call.Cap)
		}
		result := runNative(ctx, d.Run, call.Cap)
		// An unavailable body is the tier's own report that it cannot run here,
		// and it is the only verdict that sends the tier to its script side —
		// the same fall-through a missing binary takes on every other tier. A
		// Dual with no script side keeps the unavailable result, which is what
		// the runner's chain reads.
		if result.Verdict != model.VerdictUnavailable || d.Script == "" {
			return result
		}
		return runLocal(ctx, posixShell(d.Script), call.Cap)
	}
	return runLocal(ctx, ArgvFor(call.Inv), call.Cap)
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

func runLocal(ctx context.Context, argv []string, cap model.RowCap) model.RunResult {
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
		// The tool is not on this host (or was deleted between the lookups):
		// unavailable is the 127 a missing binary gives, so the chain falls to
		// the next tier and the panel names it in the skipped chain.
		return model.RunResult{Verdict: model.VerdictUnavailable, Stderr: err.Error(), ExitCode: 127}
	}
	return harvest(ctx, &localCall{
		cmd:     cmd,
		stdout:  bufio.NewReader(stdout),
		stderr:  bufio.NewReader(stderrPipe),
		process: process,
	}, cap)
}

// validText replaces bad bytes with U+FFFD: stray output from the target must not blow up the whole check.
func validText(text string) string {
	return strings.ToValidUTF8(text, "\uFFFD")
}
