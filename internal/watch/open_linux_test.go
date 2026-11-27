//go:build linux

package watch

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/procfs"

	"karma/internal/netdiag"
)

func TestOpenPoll(t *testing.T) {
	proc, err := Open(context.Background(), FamilyProcess, Options{Backend: "poll"})
	if err != nil {
		t.Fatal(err)
	}
	if proc.Name() != "poll" || !proc.Caps().Process || proc.Caps().Socket {
		t.Errorf("process source = %s %+v", proc.Name(), proc.Caps())
	}
	sock, err := Open(context.Background(), FamilySocket, Options{Backend: "poll"})
	if err != nil {
		t.Fatal(err)
	}
	if sock.Name() != "poll" || !sock.Caps().Socket || sock.Caps().Process {
		t.Errorf("socket source = %s %+v", sock.Name(), sock.Caps())
	}
	if _, err := Open(context.Background(), FamilyProcess, Options{Backend: "ebpf"}); err == nil {
		t.Fatal("an unimplemented source should be refused")
	}
	if _, err := Open(context.Background(), FamilyProcess, Options{Backend: "nope"}); err == nil {
		t.Fatal("an unknown source should be refused")
	}
	if _, err := Open(context.Background(), FamilySocket, Options{Backend: "connector"}); err == nil {
		t.Fatal("the connector must refuse a socket watch")
	}
}

func TestSocketEventsWithoutOwner(t *testing.T) {
	fs, err := procfs.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	when := time.Now()
	state := sockState{
		Key:   sockKey{Proto: "tcp", Local: "10.0.0.2:1234", Peer: "1.2.3.4:443", Inode: 9},
		State: "TIME-WAIT",
	}
	events := socketEvents(fs, []sockState{state}, nil, when)
	if len(events) != 1 {
		t.Fatalf("events = %+v", events)
	}
	event := events[0]
	if event.Sock == nil || event.Sock.PID != 0 || event.Sock.Net.State != "TIME-WAIT" || event.Sock.Net.Inode != 9 {
		t.Errorf("event = %+v", event)
	}
}

func TestSocketEventsWithOwner(t *testing.T) {
	fs, err := procfs.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state := sockState{
		Key:   sockKey{Proto: "tcp", Local: "10.0.0.2:1234", Peer: "1.2.3.4:443", Inode: 9},
		State: "ESTAB",
	}
	events := socketEvents(fs, []sockState{state}, map[uint64][]netdiag.Owner{9: {{PID: 123, Comm: "curl"}}}, time.Now())
	if len(events) != 1 || events[0].Sock == nil || events[0].Sock.PID != 123 || events[0].Sock.Comm != "curl" {
		t.Fatalf("events = %+v", events)
	}
}

// TestSocketEventsShareOnePidFacts pins the per-pid dedupe: one owner holding
// two new sockets is stated twice, and both events carry the same owner facts.
func TestSocketEventsShareOnePidFacts(t *testing.T) {
	fs, err := procfs.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first := sockState{Key: sockKey{Proto: "tcp", Local: "10.0.0.2:1234", Peer: "1.2.3.4:443", Inode: 9}, State: "ESTAB"}
	second := sockState{Key: sockKey{Proto: "tcp", Local: "10.0.0.2:5678", Peer: "1.2.3.4:443", Inode: 10}, State: "ESTAB"}
	owners := map[uint64][]netdiag.Owner{
		9:  {{PID: 123, Comm: "curl"}},
		10: {{PID: 123, Comm: "curl"}},
	}
	events := socketEvents(fs, []sockState{first, second}, owners, time.Now())
	if len(events) != 2 {
		t.Fatalf("events = %+v, want one per socket", events)
	}
	for _, event := range events {
		if event.Sock == nil || event.Sock.PID != 123 || event.Sock.Comm != "curl" {
			t.Fatalf("event = %+v, want pid 123 comm curl", event.Sock)
		}
	}
	if events[0].Sock.Net.Inode != 9 || events[1].Sock.Net.Inode != 10 {
		t.Errorf("inodes = %d %d, want 9 10", events[0].Sock.Net.Inode, events[1].Sock.Net.Inode)
	}
}
