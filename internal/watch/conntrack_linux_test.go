//go:build linux

package watch

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/ti-mo/conntrack"
)

func TestFlowEvent(t *testing.T) {
	flow := conntrack.NewFlow(6, 0,
		netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("198.51.100.25"),
		49812, 8443, 60, 0)
	event, ok := flowEvent(&flow, "NEW", time.Now())
	if !ok || event.Sock == nil {
		t.Fatalf("event = %+v, %v", event, ok)
	}
	if event.Sock.Net.Proto != "tcp" || event.Sock.Net.State != "NEW" {
		t.Errorf("net = %+v", event.Sock.Net)
	}
	if event.Sock.Net.Local != "10.0.0.2:49812" || event.Sock.Net.Peer != "198.51.100.25:8443" {
		t.Errorf("endpoints = %q -> %q", event.Sock.Net.Local, event.Sock.Net.Peer)
	}
	if event.Sock.PID != 0 {
		t.Errorf("conntrack has no owner, pid = %d", event.Sock.PID)
	}

	udp := conntrack.NewFlow(17, 0,
		netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.53"),
		49152, 53, 30, 0)
	event, ok = flowEvent(&udp, "DESTROY", time.Now())
	if !ok || event.Sock.Net.Proto != "udp" || event.Sock.Net.State != "DESTROY" {
		t.Errorf("udp event = %+v, %v", event, ok)
	}

	if _, ok := flowEvent(&conntrack.Flow{}, "NEW", time.Now()); ok {
		t.Error("a flow without a tuple should be refused")
	}
}

func TestOpenConntrackRefusesProcess(t *testing.T) {
	if _, err := Open(FamilyProcess, Options{Backend: "conntrack"}); err == nil {
		t.Fatal("conntrack must refuse a process watch")
	}
}

// TestFlowJoinMatchesBothOrientations pins the four-tuple join: an outbound
// flow names the local endpoint as source, an inbound one names it as
// destination, and both must find the socket row. An established row wins
// over a stale TIME-WAIT row of the same tuple.
func TestFlowJoinMatchesBothOrientations(t *testing.T) {
	outbound := sockKey{Proto: "tcp", Local: "10.0.0.2:49812", Peer: "198.51.100.25:443", Inode: 99}
	stale := sockKey{Proto: "tcp", Local: "198.51.100.25:443", Peer: "10.0.0.2:49812", Inode: 100}
	joiner := flowJoiner{
		ready: true, when: time.Now(),
		rows: map[sockKey]sockState{
			outbound: {Key: outbound, State: "ESTAB"},
			stale:    {Key: stale, State: "TIME-WAIT"},
		},
	}
	pid, row, joined := joiner.owner(context.Background(), "tcp", "10.0.0.2:49812", "198.51.100.25:443", time.Now())
	if !joined || row.Key.Inode != 99 {
		t.Errorf("outbound join = pid %d row %+v joined %t, want the established row", pid, row.Key, joined)
	}
	// The reversed tuple is the same flow seen from the other end.
	_, row, joined = joiner.owner(context.Background(), "tcp", "198.51.100.25:443", "10.0.0.2:49812", time.Now())
	if !joined || row.Key.Inode != 99 {
		t.Errorf("reversed join picked %+v, want the established row", row.Key)
	}
	// A tuple the table does not carry has no owner.
	if _, _, joined := joiner.owner(context.Background(), "udp", "10.0.0.2:53", "1.1.1.1:53", time.Now()); joined {
		t.Error("an unknown tuple must not join")
	}
}

// TestFlowJoinColdStartJoins pins the joiner's first use: a fresh joiner is
// not ready, and the first owner call must fill the snapshot through the
// socket-table read before it answers. The regression this pins: the ready
// check ran before the refresh, so a cold joiner never became ready and
// every conntrack flow printed pid=- while the tests, which preset ready,
// stayed green.
func TestFlowJoinColdStartJoins(t *testing.T) {
	want := sockKey{Proto: "tcp", Local: "10.0.0.2:49812", Peer: "198.51.100.25:443", Inode: 99}
	joiner := flowJoiner{
		read: func(context.Context, bool) (map[sockKey]sockState, error) {
			return map[sockKey]sockState{want: {Key: want, State: "ESTAB"}}, nil
		},
	}
	pid, row, joined := joiner.owner(context.Background(), "tcp", "10.0.0.2:49812", "198.51.100.25:443", time.Now())
	if !joined || row.Key.Inode != 99 {
		t.Fatalf("cold join = pid %d joined %t inode %d, want the snapshot row", pid, joined, row.Key.Inode)
	}
}
