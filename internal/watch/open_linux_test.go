//go:build linux

package watch

import (
	"testing"
	"time"

	"github.com/prometheus/procfs"

	"karma/internal/netdiag"
)

func TestOpenPoll(t *testing.T) {
	proc, err := Open(FamilyProcess, Options{Backend: "poll"})
	if err != nil {
		t.Fatal(err)
	}
	if proc.Name() != "poll" || !proc.Caps().Process || proc.Caps().Socket {
		t.Errorf("process source = %s %+v", proc.Name(), proc.Caps())
	}
	sock, err := Open(FamilySocket, Options{Backend: "poll"})
	if err != nil {
		t.Fatal(err)
	}
	if sock.Name() != "poll" || !sock.Caps().Socket || sock.Caps().Process {
		t.Errorf("socket source = %s %+v", sock.Name(), sock.Caps())
	}
	if _, err := Open(FamilyProcess, Options{Backend: "ebpf"}); err == nil {
		t.Fatal("an unimplemented source should be refused")
	}
	if _, err := Open(FamilyProcess, Options{Backend: "nope"}); err == nil {
		t.Fatal("an unknown source should be refused")
	}
	if _, err := Open(FamilySocket, Options{Backend: "connector"}); err == nil {
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
	events := socketEvents(fs, state, nil, when)
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
	events := socketEvents(fs, state, []netdiag.Owner{{PID: 123, FD: 3, Comm: "curl"}}, time.Now())
	if len(events) != 1 || events[0].Sock == nil || events[0].Sock.PID != 123 || events[0].Sock.Comm != "curl" {
		t.Fatalf("events = %+v", events)
	}
}
