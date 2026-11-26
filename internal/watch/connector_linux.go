//go:build linux

package watch

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"

	"karma/internal/fault"
)

// The proc connector protocol (linux/cn_proc.h): a netlink socket in the
// connector family, subscribed to CN_IDX_PROC. Each event carries a header
// (what, cpu, timestamp since boot) and a union whose fields depend on what.
const (
	cnIdxProc         = 1
	cnValProc         = 1
	procCnMcastListen = 1

	procEventFork        = 0x00000001
	procEventExec        = 0x00000002
	procEventNonzeroExit = 0x20000000
	procEventExit        = 0x80000000

	cnHeaderLen       = 20 // cb_id + seq + ack + len + flags
	procHeaderLen     = 16 // what + cpu + timestamp_ns
	forkEventLen      = procHeaderLen + 16
	execEventLen      = procHeaderLen + 8
	exitEventLen      = procHeaderLen + 24
	connectorAckLimit = 250 * time.Millisecond
)

// connectorSource is the kernel's event source for processes. It is the
// preferred process source where the kernel lets a process subscribe: an event
// is pushed at fork/exec/exit, so a process shorter than a poll interval is
// still seen. A container without CAP_NET_ADMIN refuses the subscription, and
// Open falls through to the poll.
type connectorSource struct {
	conn   *netlink.Conn
	fs     procfs.FS
	boot   time.Time
	states map[int]procState
	fork   bool
	all    bool
	self   int
	// pending holds events that arrived while the subscription was being
	// acknowledged, before Run started.
	pending []netlink.Message
}

func newConnector(opt Options) (Source, error) {
	fs, err := procfs.NewDefaultFS()
	if err != nil {
		return nil, ErrUnsupported
	}
	stat, err := fs.Stat()
	if err != nil {
		return nil, err
	}
	conn, err := netlink.Dial(unix.NETLINK_CONNECTOR, &netlink.Config{
		Groups: 1 << (cnIdxProc - 1),
	})
	if err != nil {
		return nil, err
	}
	source := &connectorSource{
		conn:   conn,
		fs:     fs,
		boot:   time.Unix(int64(stat.BootTime), 0),
		states: map[int]procState{},
		fork:   opt.Fork,
		all:    opt.All,
		self:   os.Getpid(),
	}
	if err := source.subscribe(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	// The baseline is what an exit event for a process that predates the
	// subscription still has to print.
	if prev, err := scanProcs(context.Background(), fs, nil, source.self); err == nil {
		for _, state := range prev {
			source.states[state.Key.PID] = state
		}
	}
	return source, nil
}

func (s *connectorSource) subscribe() error {
	data := make([]byte, cnHeaderLen+4)
	binary.NativeEndian.PutUint32(data[0:], cnIdxProc)
	binary.NativeEndian.PutUint32(data[4:], cnValProc)
	binary.NativeEndian.PutUint16(data[16:], 4)
	binary.NativeEndian.PutUint32(data[20:], procCnMcastListen)
	if _, err := s.conn.Send(netlink.Message{
		Header: netlink.Header{Type: netlink.Done, Flags: netlink.Request | netlink.Acknowledge},
		Data:   data,
	}); err != nil {
		return err
	}
	// The kernel answers the subscription with an ack. A short read deadline
	// keeps a kernel that stays silent from stalling the command; a timeout is
	// treated as accepted and the first Run read starts the stream.
	if err := s.conn.SetReadDeadline(time.Now().Add(connectorAckLimit)); err != nil {
		return nil
	}
	messages, err := s.conn.Receive()
	_ = s.conn.SetReadDeadline(time.Time{})
	if err != nil {
		if timeout(err) {
			return nil
		}
		return err
	}
	for _, message := range messages {
		if message.Header.Type == netlink.Error {
			if len(message.Data) < 4 {
				return errors.New("connector: short error message")
			}
			if code := int32(binary.NativeEndian.Uint32(message.Data)); code != 0 {
				return syscall.Errno(code)
			}
			continue
		}
		s.pending = append(s.pending, message)
	}
	return nil
}

func (s *connectorSource) Name() string { return "connector" }

func (s *connectorSource) Caps() Caps { return Caps{Process: true} }

func (s *connectorSource) Run(ctx context.Context, out chan<- Event) error {
	defer s.conn.Close()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		_ = fault.Catch("watch connector close", func() error {
			select {
			case <-ctx.Done():
				return s.conn.Close()
			case <-stop:
				return nil
			}
		})
	}()
	for _, message := range s.pending {
		events, err := s.events(message)
		if err != nil {
			return err
		}
		for _, event := range events {
			if !send(ctx, out, event) {
				return nil
			}
		}
	}
	s.pending = nil
	for {
		messages, err := s.conn.Receive()
		if err != nil {
			if ctx.Err() != nil || timeout(err) {
				return nil
			}
			return err
		}
		for _, message := range messages {
			events, err := s.events(message)
			if err != nil {
				return err
			}
			for _, event := range events {
				if !send(ctx, out, event) {
					return nil
				}
			}
		}
	}
}

// events turns one connector message into zero or more events. The proc_event
// layout is the one cn_proc.h states: a 16-byte header inside the cn_msg
// payload, then the union that depends on what.
func (s *connectorSource) events(message netlink.Message) ([]Event, error) {
	switch message.Header.Type {
	case netlink.Error:
		if len(message.Data) < 4 {
			return nil, errors.New("connector: short error message")
		}
		if code := int32(binary.NativeEndian.Uint32(message.Data)); code != 0 {
			return nil, syscall.Errno(code)
		}
		return nil, nil
	case netlink.Done:
	default:
		return nil, nil
	}
	if len(message.Data) < cnHeaderLen+procHeaderLen {
		return nil, nil
	}
	if binary.NativeEndian.Uint32(message.Data[0:]) != cnIdxProc ||
		binary.NativeEndian.Uint32(message.Data[4:]) != cnValProc {
		return nil, nil
	}
	payload := message.Data[cnHeaderLen:]
	at := s.boot.Add(time.Duration(binary.NativeEndian.Uint64(payload[8:])))
	switch binary.NativeEndian.Uint32(payload[0:]) {
	case procEventFork:
		if len(payload) < forkEventLen {
			return nil, nil
		}
		return s.forkEvent(payload, at), nil
	case procEventExec:
		if len(payload) < execEventLen {
			return nil, nil
		}
		return s.execEvent(payload, at), nil
	case procEventExit, procEventNonzeroExit:
		if len(payload) < exitEventLen {
			return nil, nil
		}
		return s.exitEvent(payload, at), nil
	}
	return nil, nil
}

func (s *connectorSource) forkEvent(payload []byte, at time.Time) []Event {
	if !s.fork && !s.all {
		return nil
	}
	parentTgid := at32(payload, 20)
	childPid := at32(payload, 24)
	childTgid := at32(payload, 28)
	if childPid != childTgid && !s.all {
		return nil
	}
	if childTgid == s.self || parentTgid == s.self {
		return nil
	}
	state, err := readProcStateByPID(s.fs, childTgid)
	if err != nil {
		state = procState{Key: procKey{PID: childTgid}, PPID: parentTgid}
	}
	s.states[childTgid] = state
	return []Event{{
		Time: at, Source: SourceConnector,
		Proc: &Proc{
			Kind: KindFork, PID: childTgid, PPID: parentTgid, UID: state.UID,
			Comm: state.Comm, Exe: state.Exe, Cmdline: state.Cmdline, Cwd: state.Cwd,
		},
	}}
}

func (s *connectorSource) execEvent(payload []byte, at time.Time) []Event {
	pid := at32(payload, 20)
	state, err := readProcStateByPID(s.fs, pid)
	if err != nil {
		state = procState{Key: procKey{PID: pid}}
	}
	if pid == s.self || state.PPID == s.self {
		return nil
	}
	s.states[pid] = state
	return []Event{{
		Time: at, Source: SourceConnector,
		Proc: &Proc{
			Kind: KindExec, PID: pid, PPID: state.PPID, UID: state.UID,
			Comm: state.Comm, Exe: state.Exe, Cmdline: state.Cmdline, Cwd: state.Cwd,
		},
	}}
}

func (s *connectorSource) exitEvent(payload []byte, at time.Time) []Event {
	processPid := at32(payload, 16)
	pid := at32(payload, 20)
	if processPid != pid && !s.all {
		return nil
	}
	state, ok := s.states[pid]
	if ok {
		delete(s.states, pid)
	} else {
		state = procState{Key: procKey{PID: pid}}
	}
	if state.PPID == 0 {
		state.PPID = at32(payload, 36)
	}
	if pid == s.self || state.PPID == s.self {
		return nil
	}
	code := at32(payload, 24)
	return []Event{{
		Time: at, Source: SourceConnector,
		Proc: &Proc{
			Kind: KindExit, PID: pid, PPID: state.PPID, UID: state.UID,
			Comm: state.Comm, Exe: state.Exe, Cmdline: state.Cmdline, Cwd: state.Cwd,
			ExitCode: &code,
		},
	}}
}

// at32 reads one signed 32-bit field of the proc_event payload.
func at32(payload []byte, offset int) int {
	return int(int32(binary.NativeEndian.Uint32(payload[offset:])))
}

// timeout reports a netlink read that ended on the read deadline.
func timeout(err error) bool {
	return errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, syscall.EAGAIN)
}

// connectorUnavailable formats the refusal so an explicit --source connector
// says what the kernel said.
func connectorUnavailable(err error) error {
	return fmt.Errorf("proc connector unavailable: %w", err)
}
