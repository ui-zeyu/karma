//go:build linux

package watch

import (
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
	if !ok || event.Kind != KindSocket || event.Net == nil {
		t.Fatalf("event = %+v, %v", event, ok)
	}
	if event.Net.Proto != "tcp" || event.Net.State != "NEW" {
		t.Errorf("net = %+v", event.Net)
	}
	if event.Net.Local != "10.0.0.2:49812" || event.Net.Peer != "198.51.100.25:8443" {
		t.Errorf("endpoints = %q -> %q", event.Net.Local, event.Net.Peer)
	}
	if event.PID != 0 {
		t.Errorf("conntrack has no owner, pid = %d", event.PID)
	}

	udp := conntrack.NewFlow(17, 0,
		netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.53"),
		49152, 53, 30, 0)
	event, ok = flowEvent(&udp, "DESTROY", time.Now())
	if !ok || event.Net.Proto != "udp" || event.Net.State != "DESTROY" {
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
