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
			owners := netdiag.Owners(inodes)
			for _, state := range added {
				for _, event := range socketEvents(fs, state, owners[state.Key.Inode], now) {
					if !send(ctx, out, event) {
						return nil
					}
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
			Local: netdiag.Endpoint(s.Local, s.LocalPort, ""),
			Peer:  netdiag.Endpoint(s.Peer, s.PeerPort, ""),
			Inode: s.Inode,
		}
		out[key] = sockState{Key: key, State: state, UID: int(s.UID)}
	}
	return out, nil
}

// socketEvents states one new socket: one event per owning process, or one with
// pid 0 when the inode has no local owner (the TIME-WAIT case). The owner's
// exe, cmdline, cwd and uid are read while the process still exists.
func socketEvents(fs procfs.FS, state sockState, owners []netdiag.Owner, at time.Time) []Event {
	net := &NetEvent{
		Proto: state.Key.Proto,
		State: state.State,
		Local: state.Key.Local,
		Peer:  state.Key.Peer,
		Inode: state.Key.Inode,
	}
	if len(owners) == 0 {
		return []Event{{
			Time: at, Kind: KindSocket, UID: state.UID, Net: net, Source: "poll",
		}}
	}
	sort.Slice(owners, func(i, j int) bool { return owners[i].PID < owners[j].PID })
	out := make([]Event, 0, len(owners))
	for _, owner := range owners {
		event := Event{
			Time: at, Kind: KindSocket, PID: owner.PID, Comm: owner.Comm,
			UID: state.UID, Net: net, Source: "poll",
		}
		if p, err := fs.Proc(owner.PID); err == nil {
			event.Exe, _ = p.Executable()
			if cmd, err := p.CmdLine(); err == nil {
				event.Cmdline = strings.Join(cmd, " ")
			}
			event.Cwd, _ = p.Cwd()
			if status, err := p.NewStatus(); err == nil {
				event.UID = int(status.UIDs[0])
			}
		}
		out = append(out, event)
	}
	return out
}
