//go:build linux

package watch

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"

	"karma/internal/netdiag"
)

// conntrackSource is the kernel's notification source for new and destroyed
// connections. It sees a short TCP or UDP flow that a sock_diag poll can miss,
// and it has no owner: the event is a 5-tuple, so the line prints pid=- until a
// process event or a poll attributes it.
type conntrackSource struct {
	newConn     *conntrack.Conn
	destroyConn *conntrack.Conn
	newEvents   chan conntrack.Event
	destroyed   chan conntrack.Event
	newErrors   chan error
	destroyErrs chan error
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
	return send(ctx, out, flow)
}

// flowEvent states one conntrack flow: the original tuple as the endpoints and
// the group the event came from as the state word. The flow has no process, so
// PID stays zero and the renderer prints pid=-.
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
		Time: at, Kind: KindSocket, Net: &NetEvent{Proto: proto, State: state, Local: local, Peer: peer},
		Source: "conntrack",
	}, true
}
