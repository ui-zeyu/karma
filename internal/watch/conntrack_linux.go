//go:build linux

package watch

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/prometheus/procfs"
	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"

	"karma/internal/netdiag"
)

// conntrackSource is the kernel's notification source for new and destroyed
// connections. It sees a short TCP or UDP flow that a sock_diag poll can miss.
// The flow is a 5-tuple with no owner of its own, so each flow is joined
// against the socket table by its four-tuple before it prints.
type conntrackSource struct {
	newConn     *conntrack.Conn
	destroyConn *conntrack.Conn
	newEvents   chan conntrack.Event
	destroyed   chan conntrack.Event
	newErrors   chan error
	destroyErrs chan error
	joiner      flowJoiner
}

// flowJoinTTL is how long one socket-table snapshot may answer flows. A burst
// of flows shares one read; past the bound the table is read again.
const flowJoinTTL = 200 * time.Millisecond

// flowJoiner joins a flow's four-tuple to the socket table's owner. The
// snapshot serves a burst of flows; the join answers the process that holds
// the socket while the process still exists.
type flowJoiner struct {
	fs    procfs.FS
	ready bool
	when  time.Time
	rows  map[sockKey]sockState
	// read is the socket-table read refresh uses; nil means the real
	// snapshot, and the tests inject a fixed table.
	read func(context.Context, bool) (map[sockKey]sockState, error)
}

func (j *flowJoiner) refresh(ctx context.Context, at time.Time) {
	if j.rows != nil && at.Sub(j.when) <= flowJoinTTL {
		return
	}
	read := j.read
	if read == nil {
		read = socketSnapshot
	}
	rows, err := read(ctx, true)
	if err != nil {
		return
	}
	j.rows = rows
	j.when = at
	j.ready = true
}

// owner matches a flow to a socket row and answers the row's owning process:
// the endpoints in either orientation, an established row preferred. The
// answer is the owner's pid and the socket row, or none — a flow the table
// cannot name prints pid=- as before. The first call fills the snapshot.
func (j *flowJoiner) owner(ctx context.Context, proto, local, peer string, at time.Time) (int, sockState, bool) {
	j.refresh(ctx, at)
	if !j.ready {
		return 0, sockState{}, false
	}
	var fallback sockState
	found := false
	for key, state := range j.rows {
		if key.Proto != proto {
			continue
		}
		forward := key.Local == local && key.Peer == peer
		reverse := key.Local == peer && key.Peer == local
		if !forward && !reverse {
			continue
		}
		if state.State == "ESTAB" {
			return j.holder(ctx, state), state, true
		}
		if !found {
			fallback, found = state, true
		}
	}
	if !found {
		return 0, sockState{}, false
	}
	return j.holder(ctx, fallback), fallback, true
}

// holder answers the pid that holds the row's inode, if any.
func (j *flowJoiner) holder(ctx context.Context, state sockState) int {
	if state.Key.Inode == 0 {
		return 0
	}
	owners := netdiag.Owners(ctx, map[uint64]bool{state.Key.Inode: true})[state.Key.Inode]
	if len(owners) == 0 {
		return 0
	}
	pid := owners[0].PID
	for _, owner := range owners {
		if owner.PID < pid {
			pid = owner.PID
		}
	}
	return pid
}

func newConntrack(opt Options) (Source, error) {
	config := &netlink.Config{}
	newConn, err := conntrack.Dial(config)
	if err != nil {
		return nil, err
	}
	destroyConn, err := conntrack.Dial(config)
	if err != nil {
		_ = newConn.Close()
		return nil, err
	}
	source := &conntrackSource{
		newConn:     newConn,
		destroyConn: destroyConn,
		newEvents:   make(chan conntrack.Event, 128),
		destroyed:   make(chan conntrack.Event, 128),
	}
	if fs, err := procfs.NewDefaultFS(); err == nil {
		source.joiner.fs = fs
	}
	source.newErrors, err = newConn.Listen(source.newEvents, 1, []netfilter.NetlinkGroup{netfilter.GroupCTNew})
	if err != nil {
		_ = newConn.Close()
		_ = destroyConn.Close()
		return nil, err
	}
	source.destroyErrs, err = destroyConn.Listen(source.destroyed, 1, []netfilter.NetlinkGroup{netfilter.GroupCTDestroy})
	if err != nil {
		_ = newConn.Close()
		_ = destroyConn.Close()
		return nil, err
	}
	return source, nil
}

func (s *conntrackSource) Name() string { return "conntrack" }

func (s *conntrackSource) Caps() Caps { return Caps{Socket: true} }

// conntrackUnavailable formats the refusal so an explicit --source conntrack
// says what the kernel said.
func conntrackUnavailable(err error) error {
	return fmt.Errorf("conntrack unavailable: %w", err)
}

func (s *conntrackSource) Run(ctx context.Context, out chan<- Event) error {
	defer s.newConn.Close()
	defer s.destroyConn.Close()
	newErrors, destroyErrs := s.newErrors, s.destroyErrs
	newEvents, destroyed := s.newEvents, s.destroyed
	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-newEvents:
			if !ok {
				newEvents = nil
				continue
			}
			if !s.emitFlow(ctx, out, &event, "NEW") {
				return nil
			}
		case event, ok := <-destroyed:
			if !ok {
				destroyed = nil
				continue
			}
			if !s.emitFlow(ctx, out, &event, "DESTROY") {
				return nil
			}
		case err, ok := <-newErrors:
			if !ok {
				newErrors = nil
				continue
			}
			if err != nil {
				return err
			}
		case err, ok := <-destroyErrs:
			if !ok {
				destroyErrs = nil
				continue
			}
			if err != nil {
				return err
			}
		}
	}
}

func (s *conntrackSource) emitFlow(ctx context.Context, out chan<- Event, event *conntrack.Event, state string) bool {
	if event == nil || event.Flow == nil {
		return true
	}
	flow, ok := flowEvent(event.Flow, state, time.Now())
	if !ok {
		return true
	}
	// The flow has no process of its own; the socket table the four-tuple
	// names does. A join that answers carries the owner's image and the
	// inode that ties the flow to it.
	if pid, row, joined := s.joiner.owner(ctx, flow.Sock.Net.Proto, flow.Sock.Net.Local, flow.Sock.Net.Peer, flow.Time); joined && pid != 0 {
		flow.Sock.Net.Inode = row.Key.Inode
		flow.Sock.UID = row.UID
		flow.Sock.PID = pid
		if pid != 0 {
			if proc, err := readProcStateByPID(s.joiner.fs, pid); err == nil {
				flow.Sock.Comm = proc.Comm
				flow.Sock.Exe = proc.Exe
				flow.Sock.Cmdline = proc.Cmdline
				flow.Sock.Args = proc.Args
				flow.Sock.Cwd = proc.Cwd
				if proc.UID != 0 {
					flow.Sock.UID = proc.UID
				}
			}
		}
	}
	return send(ctx, out, flow)
}

// flowEvent states one conntrack flow: the original tuple as the endpoints and
// the group the event came from as the state word. The flow has no process, so
// the pid stays 0 until the four-tuple join answers.
func flowEvent(flow *conntrack.Flow, state string, at time.Time) (Event, bool) {
	tuple := flow.TupleOrig
	if !tuple.IP.SourceAddress.IsValid() || !tuple.IP.DestinationAddress.IsValid() {
		return Event{}, false
	}
	proto := "tcp"
	switch tuple.Proto.Protocol {
	case 1:
		proto = "icmp"
	case 17:
		proto = "udp"
	case 6:
	default:
		proto = fmt.Sprintf("ip-%d", tuple.Proto.Protocol)
	}
	local := netdiag.Endpoint(net.IP(tuple.IP.SourceAddress.AsSlice()), tuple.Proto.SourcePort, "")
	peer := netdiag.Endpoint(net.IP(tuple.IP.DestinationAddress.AsSlice()), tuple.Proto.DestinationPort, "")
	return Event{
		Time: at, Source: SourceConntrack,
		Sock: &Sock{Net: NetEvent{Proto: proto, State: state, Local: local, Peer: peer}},
	}, true
}
