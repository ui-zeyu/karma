//go:build linux

package watch

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/prometheus/procfs"
)

// procPoll is the universal process source: one /proc scan per tick, keyed by
// pid and starttime so a reused pid is a new event, with the full facts read
// only for keys the previous scan did not carry.
type procPoll struct {
	interval time.Duration
	all      bool
}

func (p *procPoll) Name() string { return "poll" }

func (p *procPoll) Caps() Caps { return Caps{Process: true} }

func (p *procPoll) Run(ctx context.Context, out chan<- Event) error {
	fs, err := procfs.NewDefaultFS()
	if err != nil {
		return ErrUnsupported
	}
	prev := map[procKey]procState{}
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	self := os.Getpid()
	first := true
	for {
		cur, err := scanProcs(ctx, fs, prev, self)
		if err != nil {
			return err
		}
		started, ended := diffProc(prev, cur)
		if first && !p.all {
			started = nil
		}
		now := time.Now()
		for _, state := range ended {
			if !deliver(ctx, out, state.event(KindExit, now)) {
				return nil
			}
		}
		for _, state := range started {
			if !deliver(ctx, out, state.event(KindExec, now)) {
				return nil
			}
		}
		prev = cur
		first = false
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// scanProcs reads the table once. stat is read for every process because the
// starttime is the key; the rest of a process's facts are read only when the
// key is new. The watcher and its own children are left out: the annotator's
// package query is a process too, and a watcher that reports its own lookup as
// target activity is noise.
func scanProcs(ctx context.Context, fs procfs.FS, prev map[procKey]procState, self int) (map[procKey]procState, error) {
	procs, err := fs.AllProcs()
	if err != nil {
		return nil, err
	}
	out := make(map[procKey]procState, len(procs))
	for _, p := range procs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		stat, err := p.Stat()
		if err != nil {
			continue
		}
		if p.PID == self || stat.PPID == self {
			continue
		}
		key := procKey{PID: p.PID, Start: stat.Starttime}
		if old, ok := prev[key]; ok {
			out[key] = old
			continue
		}
		out[key] = procFacts(p, stat)
	}
	return out, nil
}

// procFacts reads the facts the watcher prints for one process. stat is passed
// in because every scan reads it for the key; the rest is read here, only for a
// key the previous scan did not carry.
func procFacts(p procfs.Proc, stat procfs.ProcStat) procState {
	state := procState{Key: procKey{PID: p.PID, Start: stat.Starttime}, PPID: stat.PPID, Comm: stat.Comm}
	if status, err := p.NewStatus(); err == nil {
		state.UID = int(status.UIDs[0])
	}
	if cmd, err := p.CmdLine(); err == nil {
		state.Args = cmd
		state.Cmdline = strings.Join(cmd, " ")
	}
	state.Exe, _ = p.Executable()
	state.Cwd, _ = p.Cwd()
	return state
}

// readProcStateByPID is procFacts for one pid, used by the connector source at
// an exec event.
func readProcStateByPID(fs procfs.FS, pid int) (procState, error) {
	p, err := fs.Proc(pid)
	if err != nil {
		return procState{}, err
	}
	stat, err := p.Stat()
	if err != nil {
		return procState{}, err
	}
	return procFacts(p, stat), nil
}

func (s procState) event(kind Kind, at time.Time) Event {
	return Event{
		Time:   at,
		Source: SourcePoll,
		Proc: &Proc{
			Kind:    kind,
			PID:     s.Key.PID,
			PPID:    s.PPID,
			UID:     s.UID,
			Comm:    s.Comm,
			Exe:     s.Exe,
			Cmdline: s.Cmdline,
			Args:    s.Args,
			Cwd:     s.Cwd,
		},
	}
}
