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

// tupleKey is a socket row's endpoints without the inode: the join's key. It
// is derived from the row's own sockKey, so the join never restates an
// endpoint the snapshot already spelled.
type tupleKey struct {
	Proto string
	Local string
	Peer  string
}

// flowJoiner joins a flow's four-tuple to the socket table's owner. The
// snapshot serves a burst of flows; the join answers the process that holds
// the socket while the process still exists.
type flowJoiner struct {
	fs    procfs.FS
	ready bool
	when  time.Time
	// forward and reverse index one snapshot by (proto, local, peer) in both
	// orientations, so a flow's join is one map lookup.
	forward map[tupleKey]sockState
	reverse map[tupleKey]sockState
	// pid holds the owner each snapshot inode resolves to, and procs the
	// image facts per owner pid; both live exactly as long as the snapshot,
	// so one TTL carries one socket read, one owner walk and one /proc read
	// per distinct pid.
	pid   map[uint64]int
	procs map[int]procState
	// read is the socket-table read refresh uses; nil means the real
	// snapshot, and the tests inject a fixed table.
	read func(context.Context, bool) (map[sockKey]sockState, error)
	// ownersRead is the owner walk refresh uses; nil means the real
	// netdiag.Owners, and the tests inject a fixed answer.
	ownersRead func(context.Context, map[uint64]bool) map[uint64][]netdiag.Owner
}

func (j *flowJoiner) refresh(ctx context.Context, at time.Time) {
	if j.forward != nil && at.Sub(j.when) <= flowJoinTTL {
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
	j.index(rows)
	j.resolveOwners(ctx)
	j.when = at
	j.ready = true
}

// resolveOwners answers the snapshot's holders in one /proc walk: refresh
// resolves every inode the table carried once, and holder reads the answer
// from the map for as long as the snapshot is fresh.
func (j *flowJoiner) resolveOwners(ctx context.Context) {
	read := j.ownersRead
	if read == nil {
		read = netdiag.Owners
	}
	inodes := make(map[uint64]bool, len(j.forward))
	for _, state := range j.forward {
		if state.Key.Inode != 0 {
			inodes[state.Key.Inode] = true
		}
	}
	owners := read(ctx, inodes)
	j.pid = make(map[uint64]int, len(owners))
	for inode, held := range owners {
		if len(held) == 0 {
			continue
		}
		pid := held[0].PID
		for _, owner := range held[1:] {
			if owner.PID < pid {
				pid = owner.PID
			}
		}
		j.pid[inode] = pid
	}
	j.procs = map[int]procState{}
}

// index builds the two orientation maps from one snapshot's rows. A tuple
// with several rows — a stale TIME-WAIT beside a live connection — answers
// the established row.
func (j *flowJoiner) index(rows map[sockKey]sockState) {
	forward := make(map[tupleKey]sockState, len(rows))
	reverse := make(map[tupleKey]sockState, len(rows))
	for _, state := range rows {
		if held, ok := forward[tupleKey{state.Key.Proto, state.Key.Local, state.Key.Peer}]; !ok || preferEstab(held, state) {
			forward[tupleKey{state.Key.Proto, state.Key.Local, state.Key.Peer}] = state
		}
		if held, ok := reverse[tupleKey{state.Key.Proto, state.Key.Peer, state.Key.Local}]; !ok || preferEstab(held, state) {
			reverse[tupleKey{state.Key.Proto, state.Key.Peer, state.Key.Local}] = state
		}
	}
	j.forward, j.reverse = forward, reverse
}

// preferEstab reports whether next should replace held as the tuple's answer:
// an established row wins, whichever orientation it arrived in.
func preferEstab(held, next sockState) bool {
	return next.State == "ESTAB" && held.State != "ESTAB"
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
	key := tupleKey{Proto: proto, Local: local, Peer: peer}
	forward, okF := j.forward[key]
	reverse, okR := j.reverse[key]
	var state sockState
	switch {
	case okF && forward.State == "ESTAB":
		state = forward
	case okR && reverse.State == "ESTAB":
		state = reverse
	case okF:
		state = forward
	case okR:
		state = reverse
	default:
		return 0, sockState{}, false
	}
	return j.holder(state), state, true
}

// holder answers the pid that holds the row's inode, from the batch the last
// refresh resolved.
func (j *flowJoiner) holder(state sockState) int {
	return j.pid[state.Key.Inode]
}

// proc reads the image facts a joined flow prints for its owner, once per
// pid and snapshot.
func (j *flowJoiner) proc(pid int) (procState, bool) {
	if state, ok := j.procs[pid]; ok {
		return state, true
	}
	state, err := readProcStateByPID(j.fs, pid)
	if err != nil {
		return procState{}, false
	}
	j.procs[pid] = state
	return state, true
}

// newConntrack opens two netfilter sockets and joins their flow groups.
// Nothing in the open exchanges a message with the kernel: the dial only
// opens and binds the socket, and Listen only joins the groups and starts
// background receivers, so an Open call cannot park on a silent kernel. The
// ti-mo wrapper exposes no deadline surface, and the flow reads run on the
// workers' own schedule after the open returned.
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

func (s *conntrackSource) Caps() Caps { return Caps{Socket: true, Push: true} }

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
		if proc, ok := s.joiner.proc(pid); ok {
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
	return deliver(ctx, out, flow)
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
	local := netdiag.Endpoint(net.IP(tuple.IP.SourceAddress.AsSlice()), tuple.Proto.SourcePort)
	peer := netdiag.Endpoint(net.IP(tuple.IP.DestinationAddress.AsSlice()), tuple.Proto.DestinationPort)
	return Event{
		Time: at, Source: SourceConntrack,
		Sock: &Sock{Net: NetEvent{Proto: proto, State: state, Local: local, Peer: peer}},
	}, true
}
