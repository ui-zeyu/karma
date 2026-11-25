//go:build linux

package watch

import (
	"encoding/binary"
	"errors"
	"syscall"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/prometheus/procfs"
)

// connectorMessage builds one proc_event as the kernel sends it: the cn_msg
// header, then what/cpu/timestamp, then the union fields.
func connectorMessage(what uint32, timestamp uint64, fields ...uint32) netlink.Message {
	data := make([]byte, cnHeaderLen+exitEventLen)
	binary.NativeEndian.PutUint32(data[0:], cnIdxProc)
	binary.NativeEndian.PutUint32(data[4:], cnValProc)
	binary.NativeEndian.PutUint16(data[16:], exitEventLen)
	binary.NativeEndian.PutUint32(data[20:], what)
	binary.NativeEndian.PutUint64(data[28:], timestamp)
	for index, field := range fields {
		binary.NativeEndian.PutUint32(data[36+index*4:], field)
	}
	return netlink.Message{Header: netlink.Header{Type: netlink.Done}, Data: data}
}

func connectorForTest(t *testing.T) *connectorSource {
	t.Helper()
	fs, err := procfs.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &connectorSource{
		fs:     fs,
		boot:   time.Unix(1000, 0),
		states: map[int]procState{},
		self:   999,
	}
}

func TestConnectorExecEvent(t *testing.T) {
	source := connectorForTest(t)
	events, err := source.events(connectorMessage(procEventExec, uint64(5*time.Second), 123, 123))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != KindExec || events[0].PID != 123 {
		t.Fatalf("events = %+v", events)
	}
	if !events[0].Time.Equal(time.Unix(1005, 0)) {
		t.Errorf("time = %v, want the boot time plus the event timestamp", events[0].Time)
	}
}

func TestConnectorExitEvent(t *testing.T) {
	for _, what := range []uint32{procEventExit, procEventNonzeroExit} {
		source := connectorForTest(t)
		source.states[123] = procState{Key: procKey{PID: 123}, PPID: 7, UID: 0, Comm: "qqq"}
		events, err := source.events(connectorMessage(what, 0, 123, 123, 7, 0, 7, 7))
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 1 || events[0].Kind != KindExit || events[0].Comm != "qqq" {
			t.Fatalf("events = %+v", events)
		}
		if events[0].ExitCode == nil || *events[0].ExitCode != 7 {
			t.Errorf("exit code = %v, want 7", events[0].ExitCode)
		}
		if _, ok := source.states[123]; ok {
			t.Error("the exit should drop the cached state")
		}
	}
}

func TestConnectorThreadEvents(t *testing.T) {
	source := connectorForTest(t)
	// A thread fork carries a pid that differs from the tgid; without --all it
	// is not a process event.
	events, err := source.events(connectorMessage(procEventFork, 0, 7, 7, 124, 123))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("thread fork = %+v, want nothing without --all", events)
	}
	source.all = true
	source.fork = true
	events, err = source.events(connectorMessage(procEventFork, 0, 7, 7, 124, 123))
	if err != nil || len(events) != 1 || events[0].Kind != KindFork {
		t.Fatalf("--all fork = %+v, %v", events, err)
	}
}

func TestConnectorError(t *testing.T) {
	source := connectorForTest(t)
	data := make([]byte, 4)
	binary.NativeEndian.PutUint32(data, 13)
	_, err := source.events(netlink.Message{Header: netlink.Header{Type: netlink.Error}, Data: data})
	if !errors.Is(err, syscall.EACCES) {
		t.Fatalf("error = %v, want EACCES", err)
	}
}

func TestConnectorIgnoresOtherIDs(t *testing.T) {
	source := connectorForTest(t)
	message := connectorMessage(procEventExec, 0, 123, 123)
	binary.NativeEndian.PutUint32(message.Data[0:], 2)
	events, err := source.events(message)
	if err != nil || len(events) != 0 {
		t.Fatalf("foreign connector id = %+v, %v", events, err)
	}
}
