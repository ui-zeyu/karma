package watch

import (
	"context"
	"errors"
	"time"
)

// Kind is what one event describes.
type Kind string

const (
	KindExec   Kind = "exec"
	KindExit   Kind = "exit"
	KindFork   Kind = "fork"
	KindSocket Kind = "socket"
)

// Family is the view a command asked for: process events or socket events.
type Family uint8

const (
	FamilyProcess Family = iota
	FamilySocket
)

// Caps states the event families a source can produce.
type Caps struct {
	Process bool
	Socket  bool
}

// NetEvent is one socket's identity: the protocol, the state word, the two
// endpoints, and the inode that ties it to a process.
type NetEvent struct {
	Proto string `json:"proto"`
	State string `json:"state"`
	Local string `json:"local"`
	Peer  string `json:"peer"`
	Inode uint64 `json:"inode"`
}

// Event is one observation. PID 0 on a socket means no local process was found
// for the inode (the TIME-WAIT case); the renderer prints it as pid=-.
type Event struct {
	Time    time.Time `json:"time"`
	Kind    Kind      `json:"kind"`
	PID     int       `json:"pid"`
	PPID    int       `json:"ppid,omitempty"`
	UID     int       `json:"uid"`
	Comm    string    `json:"comm,omitempty"`
	Exe     string    `json:"exe,omitempty"`
	Cmdline string    `json:"cmdline,omitempty"`
	Cwd     string    `json:"cwd,omitempty"`
	Net     *NetEvent `json:"net,omitempty"`
	// ExitCode is the connector's exit status; the poll source does not know
	// it and leaves the pointer nil.
	ExitCode *int     `json:"exit_code,omitempty"`
	Flags    []string `json:"flags,omitempty"`
	// Source is the backend that produced the event (poll, connector, conntrack).
	Source string `json:"source,omitempty"`
	// Origin, Reach and Severity are the audit's judgment of the image an exec
	// runs, or of the owner an owned socket names. Exit and fork events run no
	// image, and a socket with no known owner leaves them empty.
	Origin   string `json:"origin,omitempty"`
	Reach    string `json:"reach,omitempty"`
	Severity string `json:"severity,omitempty"`
}

// Source produces events until the context ends. Run must not close out; the
// caller owns the channel, and every send selects on the context so a stopped
// reader does not leave the source blocked.
type Source interface {
	Name() string
	Caps() Caps
	Run(ctx context.Context, out chan<- Event) error
}

// Options are the poll's own settings. Backend chooses a source; the empty
// string and "auto" both take the first available one.
type Options struct {
	Interval time.Duration
	All      bool
	Fork     bool
	Backend  string
	JSON     bool
}

// ErrUnsupported reports that this platform has no watch source at all.
var ErrUnsupported = errors.New("watch needs Linux /proc and sock_diag")
