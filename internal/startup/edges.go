package startup

import (
	"encoding/json"

	"karma/internal/trust"
)

// Surface is the family of activation mechanism the trigger belongs to.
type Surface string

const (
	SurfaceSystemd    Surface = "systemd"
	SurfaceProfile    Surface = "profile"
	SurfaceInit       Surface = "init"
	SurfaceCron       Surface = "cron"
	SurfaceLoader     Surface = "loader"
	SurfaceUdev       Surface = "udev"
	SurfaceSSH        Surface = "ssh"
	SurfacePAM        Surface = "pam"
	SurfaceSupervisor Surface = "supervisor"
	SurfaceXdg        Surface = "xdg"
	SurfaceApt        Surface = "apt"
	SurfaceModule     Surface = "module"
	SurfaceSystem     Surface = "system"
)

// Phase is when the trigger acts. The audit maps a phase and a subject onto
// its own authority reach; this vocabulary stays about time.
type Phase uint8

const (
	// BootEnabled acts at boot and the init is committed to it: the unit is
	// enabled, the runlevel link exists.
	BootEnabled Phase = iota
	// BootStaged is present for boot but the init has not committed to it.
	BootStaged
	// Login acts when a login session opens.
	Login
	// Session acts inside an interactive session.
	Session
	// Scheduled acts on a timer.
	Scheduled
	// Device acts when a device appears.
	Device
)

var phaseNames = [...]string{"boot-enabled", "boot-staged", "login", "session", "scheduled", "device"}

// String renders the phase the way the audit's panels print it.
func (p Phase) String() string {
	if int(p) >= len(phaseNames) {
		return "unknown"
	}
	return phaseNames[p]
}

// MarshalJSON writes the phase as the word the panels print.
func (p Phase) MarshalJSON() ([]byte, error) { return json.Marshal(p.String()) }

// SubjectClass is the structural class of the account an activation runs as.
type SubjectClass uint8

const (
	// AccountNamed is one specific account; Subject.User names it.
	AccountNamed SubjectClass = iota
	// AccountRoot is root itself.
	AccountRoot
	// AccountAll is every account: loader preloads run in each process.
	AccountAll
	// AccountLogin is whichever account opens the session.
	AccountLogin
	// AccountDynamic is a systemd dynamic user.
	AccountDynamic
)

// Subject is the account an activation runs as.
type Subject struct {
	Class SubjectClass `json:"class"`
	// User carries the account name when Class is AccountNamed.
	User string `json:"user,omitempty"`
}

var subjectClassNames = [...]string{"named", "root", "all", "login", "dynamic"}

// String renders the subject class the way the audit's panels print it.
func (c SubjectClass) String() string {
	if int(c) >= len(subjectClassNames) {
		return "named"
	}
	return subjectClassNames[c]
}

// MarshalJSON writes the subject class as its word.
func (c SubjectClass) MarshalJSON() ([]byte, error) { return json.Marshal(c.String()) }

// Account returns the subject for a named account.
func Account(name string) Subject { return Subject{Class: AccountNamed, User: name} }

// IsRoot reports whether the subject is root: the root class, or a named
// account that is root. A unit that writes User=root states root authority in
// its own file, and the judgment reads it as root.
func (s Subject) IsRoot() bool {
	return s.Class == AccountRoot || (s.Class == AccountNamed && s.User == "root")
}

// String renders the subject the way the audit's panels print it.
func (s Subject) String() string {
	switch s.Class {
	case AccountNamed:
		return s.User
	case AccountRoot:
		return "root"
	case AccountAll:
		return "all"
	case AccountLogin:
		return "login"
	case AccountDynamic:
		return "dynamic"
	}
	return ""
}

// Kind is what the target is to the trigger.
type Kind string

const (
	// Exec runs the target as a program.
	Exec Kind = "exec"
	// Source reads the target into the current shell.
	Source Kind = "source"
	// Env puts the target's path into a variable a later session can use.
	Env Kind = "env"
	// Config is read as configuration rather than executed.
	Config Kind = "config"
	// Preload hands the target to the dynamic loader before the program runs.
	Preload Kind = "preload"
	// Library is mapped into a process the system runs (a PAM or NSS module).
	Library Kind = "library"
)

// Mechanism is how the trigger acts on the target: a systemd key, a shell
// statement, a udev key. The set is open; each parser owns its names.
type Mechanism string

// Edge is one trigger → mechanism → target relation. The parser states the
// structure; the facts on both ends let the judge answer what the relation
// means without parsing a name.
type Edge struct {
	Surface Surface `json:"surface"`
	Phase   Phase   `json:"phase"`
	Subject Subject `json:"subject"`
	Trigger string  `json:"trigger"`
	Line    int     `json:"line,omitempty"`
	// Source is the raw trigger line the edge was read from, trimmed: the
	// quote a finding can carry.
	Source    string    `json:"source,omitempty"`
	Mechanism Mechanism `json:"mechanism,omitempty"`
	Target    string    `json:"target,omitempty"`
	Kind      Kind      `json:"kind"`
	// TriggerFacts and TargetFacts are the provenance of the two ends. They
	// are render-side state: the origins they carry are judged facts, and
	// the JSON answer carries the judged edges alone.
	TriggerFacts trust.Facts `json:"-"`
	TargetFacts  trust.Facts `json:"-"`
	// Dynamic is a target the collector could not name statically (a variable
	// command, a PATH lookup). It is reported as coverage, never judged.
	Dynamic bool `json:"dynamic,omitempty"`
	// Context is a declared directory or path a unit works in
	// (WorkingDirectory, RuntimeDirectory, ...). The graph renders it as a
	// relation; the judge does not turn it into a finding of its own unless
	// the declared write access names a dangerous target.
	Context bool `json:"context,omitempty"`
	// Note is the row's own remaining fields where a parser reads a table
	// line by line (a fstab row's filesystem type and options, a crypttab
	// row's device and key file). Two spellings exist and each has one
	// machine reader: a fstab row's note is the raw fields joined by spaces
	// (fstabType takes fields[0]); a mount unit's What note is
	// "type=<fstype> options=<opts>". The judge reads the fstab spelling on
	// the Mechanism=="fstab" path only.
	Note string `json:"note,omitempty"`
}

// rawEdge is an edge before its ends' facts are read.
type rawEdge struct {
	surface Surface
	phase   Phase
	subject Subject
	trigger string
	// line is the 1-based line in trigger the edge was read from. A parser
	// reading a command out of a larger line passes that line as the base;
	// shellEdges adds the command's own 1-based offset.
	line      int
	mechanism Mechanism
	target    string
	kind      Kind
	dynamic   bool
	context   bool
	note      string
}
