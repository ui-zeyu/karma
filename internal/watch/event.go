package watch

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"karma/internal/audit"
)

// Kind is what one process event describes.
type Kind string

const (
	KindExec Kind = "exec"
	KindExit Kind = "exit"
	KindFork Kind = "fork"
)

// Family is the view a command asked for: process events or socket events.
type Family uint8

const (
	FamilyProcess Family = iota
	FamilySocket
)

// String is the family's name in the watcher's stderr banner.
func (f Family) String() string {
	if f == FamilySocket {
		return "socket"
	}
	return "proc"
}

// Caps states what a source can produce: the event families it fills, and
// whether it runs off kernel notifications instead of a poll loop.
type Caps struct {
	Process bool
	Socket  bool
	Push    bool
}

// SourceName is the backend that produced an event.
type SourceName string

const (
	SourcePoll      SourceName = "poll"
	SourceConnector SourceName = "connector"
	SourceConntrack SourceName = "conntrack"
)

// NetEvent is one socket's identity: the protocol, the state word, the two
// endpoints, and the inode that ties it to a process.
type NetEvent struct {
	Proto string `json:"proto"`
	State string `json:"state"`
	Local string `json:"local"`
	Peer  string `json:"peer"`
	Inode uint64 `json:"inode"`
}

// Proc is one process observation.
type Proc struct {
	Kind    Kind     `json:"kind"`
	PID     int      `json:"pid"`
	PPID    int      `json:"ppid,omitempty"`
	UID     int      `json:"uid,omitempty"`
	Comm    string   `json:"comm,omitempty"`
	Exe     string   `json:"exe,omitempty"`
	Cmdline string   `json:"cmdline,omitempty"`
	Args    []string `json:"-"`
	Cwd     string   `json:"cwd,omitempty"`
	// ExitCode is the connector's exit status; the poll source does not know
	// it and leaves the pointer nil.
	ExitCode *int `json:"exit_code,omitempty"`
	// Script is the script path an interpreter's command line carries. The
	// judgment reads the script beside the image.
	Script string `json:"script,omitempty"`
}

// Sock is one socket observation with its local owner, when the owner table
// answered. PID 0 is the TIME-WAIT case: the socket has no local process.
type Sock struct {
	Net     NetEvent `json:"net"`
	PID     int      `json:"pid"`
	UID     int      `json:"uid,omitempty"`
	Comm    string   `json:"comm,omitempty"`
	Exe     string   `json:"exe,omitempty"`
	Cmdline string   `json:"cmdline,omitempty"`
	Args    []string `json:"-"`
	// Script is the script path the owner's interpreter carries, read beside
	// the image the way a process event's script is.
	Script string `json:"script,omitempty"`
	Cwd    string `json:"cwd,omitempty"`
}

// Verdict is the audit's judgment of the image an event runs, or of the image
// a socket's owner runs. Exit and fork events run no image, and a socket with
// no known owner leaves it unset.
type Verdict struct {
	Origin   audit.Origin   `json:"origin"`
	Reach    audit.Reach    `json:"reach"`
	Severity audit.Severity `json:"severity"`
}

// MarshalJSON prints the three words the lines print, so the JSON stream and
// the text stream read the same vocabulary.
func (v Verdict) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Origin   string `json:"origin"`
		Reach    string `json:"reach"`
		Severity string `json:"severity"`
	}{v.Origin.String(), v.Reach.String(), v.Severity.String()})
}

// Flag is one structural fact the annotator distilled from an event's image,
// its working directory and its command line.
type Flag string

const (
	FlagDeleted       Flag = "deleted"
	FlagNoImage       Flag = "no-image"
	FlagUnowned       Flag = "unowned"
	FlagUnownedExec   Flag = "unowned-exec"
	FlagAdmin         Flag = "admin"
	FlagHidden        Flag = "hidden"
	FlagWritable      Flag = "writable"
	FlagAdminCwd      Flag = "admin-cwd"
	FlagUnownedScript Flag = "unowned-script"
	FlagAdminScript   Flag = "admin-script"
)

// flagOrder is the order flags print in, so a line reads the same whatever
// sequence the facts were gathered in.
var flagOrder = []Flag{
	FlagDeleted, FlagNoImage, FlagUnowned, FlagUnownedExec, FlagAdmin, FlagHidden,
	FlagWritable, FlagAdminCwd, FlagUnownedScript, FlagAdminScript,
}

// Event is one observation: the source that produced it, exactly one body,
// and the flags and verdict the pipeline attached.
type Event struct {
	Seq  uint64    `json:"seq"`
	Time time.Time `json:"time"`
	// Source is the backend that produced the event.
	Source SourceName `json:"source"`
	// Exactly one of Proc and Sock is set.
	Proc *Proc `json:"proc,omitempty"`
	Sock *Sock `json:"sock,omitempty"`
	// Verdict is set once the pipeline judged the event's image.
	Verdict *Verdict `json:"verdict,omitempty"`
	Flags   []Flag   `json:"flags,omitempty"`
}

// Source produces events until the context ends. Run must not close out; the
// caller owns the channel, and every send selects on the context so a stopped
// reader does not leave the source blocked.
type Source interface {
	Name() string
	Caps() Caps
	Run(ctx context.Context, out chan<- Event) error
}

// Options are the settings a source is built with. Backend chooses a source;
// the empty string and "auto" both take the first available one.
type Options struct {
	Interval time.Duration
	All      bool
	Fork     bool
	Backend  string
}

// RunOptions are the output options of Run and RunWith.
type RunOptions struct {
	JSON bool
}

// ErrUnsupported reports that this platform has no watch source at all.
var ErrUnsupported = errors.New("watch needs Linux /proc and sock_diag")
