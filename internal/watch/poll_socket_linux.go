//go:build linux

package watch

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/procfs"

	"karma/internal/netdiag"
)

// socketPoll is the universal socket source: one sock_diag dump per tick, the
// key carrying the inode so a state change is the same socket while the
// TIME-WAIT socket the kernel creates after close is a new row. The owner is
// resolved only for new inodes.
type socketPoll struct {
	interval time.Duration
	all      bool
}

func (p *socketPoll) Name() string { return "poll" }

func (p *socketPoll) Caps() Caps { return Caps{Socket: true} }

func (p *socketPoll) Run(ctx context.Context, out chan<- Event) error {
	fs, err := procfs.NewDefaultFS()
	if err != nil {
		return ErrUnsupported
	}
	prev := map[sockKey]sockState{}
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	first := true
	for {
		cur, err := socketSnapshot(ctx, p.all)
		if err != nil {
			return err
		}
		added := newSockets(prev, cur)
		if first && !p.all {
			added = nil
		}
		now := time.Now()
		if len(added) > 0 {
			inodes := make(map[uint64]bool, len(added))
			for _, state := range added {
				if state.Key.Inode != 0 {
					inodes[state.Key.Inode] = true
				}
			}
			owners := netdiag.Owners(ctx, inodes)
			for _, event := range socketEvents(fs, added, owners, now) {
				if !deliver(ctx, out, event) {
					return nil
				}
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

// socketSnapshot reads the table into the state map. A listening socket and an
// unconnected UDP socket are the standing furniture ss already lists; they print
// only with --all, where a new listener is itself the finding.
func socketSnapshot(ctx context.Context, all bool) (map[sockKey]sockState, error) {
	socks, err := netdiag.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[sockKey]sockState, len(socks))
	for _, s := range socks {
		state := netdiag.StateWord(s.Netid, s.State)
		if !all && (state == "LISTEN" || (s.Netid == "udp" && state == "UNCONN")) {
			continue
		}
		key := sockKey{
			Proto: s.Netid,
			Local: netdiag.Endpoint(s.Local, s.LocalPort),
			Peer:  netdiag.Endpoint(s.Peer, s.PeerPort),
			Inode: s.Inode,
		}
		out[key] = sockState{Key: key, State: state, UID: int(s.UID)}
	}
	return out, nil
}

// ownerFacts is one owner's image facts, read once per pid and shared by every
// event the pid holds in the tick.
type ownerFacts struct {
	exe     string
	args    []string
	cmdline string
	cwd     string
	uid     int
}

// readOwnerFacts reads the facts socketEvents prints for one owner. uid stays
// negative when /proc did not answer, so the socket row's uid survives.
func readOwnerFacts(fs procfs.FS, pid int) ownerFacts {
	facts := ownerFacts{uid: -1}
	p, err := fs.Proc(pid)
	if err != nil {
		return facts
	}
	facts.exe, _ = p.Executable()
	if cmd, err := p.CmdLine(); err == nil {
		facts.args = cmd
		facts.cmdline = strings.Join(cmd, " ")
	}
	facts.cwd, _ = p.Cwd()
	if status, err := p.NewStatus(); err == nil {
		facts.uid = int(status.UIDs[0])
	}
	return facts
}

// socketEvents states one tick's new sockets: one event per owning process, or
// one with pid 0 when an inode has no local owner (the TIME-WAIT case). The
// owner set is deduplicated by pid first, so a process holding several new
// sockets is read once and its facts fill every event it owns.
func socketEvents(fs procfs.FS, added []sockState, owners map[uint64][]netdiag.Owner, at time.Time) []Event {
	pids := map[int]bool{}
	for _, state := range added {
		for _, owner := range owners[state.Key.Inode] {
			pids[owner.PID] = true
		}
	}
	facts := make(map[int]ownerFacts, len(pids))
	for pid := range pids {
		facts[pid] = readOwnerFacts(fs, pid)
	}
	out := make([]Event, 0)
	for _, state := range added {
		net := NetEvent{
			Proto: state.Key.Proto,
			State: state.State,
			Local: state.Key.Local,
			Peer:  state.Key.Peer,
			Inode: state.Key.Inode,
		}
		batch := owners[state.Key.Inode]
		if len(batch) == 0 {
			out = append(out, Event{Time: at, Source: SourcePoll, Sock: &Sock{Net: net, UID: state.UID}})
			continue
		}
		sort.Slice(batch, func(i, j int) bool { return batch[i].PID < batch[j].PID })
		for _, owner := range batch {
			read := facts[owner.PID]
			sock := &Sock{Net: net, PID: owner.PID, Comm: owner.Comm, UID: state.UID}
			sock.Exe, sock.Args, sock.Cmdline, sock.Cwd = read.exe, read.args, read.cmdline, read.cwd
			if read.uid >= 0 {
				sock.UID = read.uid
			}
			out = append(out, Event{Time: at, Source: SourcePoll, Sock: sock})
		}
	}
	return out
}
