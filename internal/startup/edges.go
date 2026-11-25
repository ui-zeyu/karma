package startup

import "karma/internal/trust"

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
)

// Reach is when the trigger runs.
type Reach string

const (
	BootEnabled Reach = "boot-enabled"
	BootStaged  Reach = "boot-staged"
	Login       Reach = "login"
	Session     Reach = "session"
	Scheduled   Reach = "scheduled"
	Device      Reach = "device"
)

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
)

// Edge is one trigger → mechanism → target relation. The parser states the
// structure; the facts on both ends let the judge answer what the relation
// means without parsing a name.
type Edge struct {
	Surface   Surface
	Reach     Reach
	AS        string
	Trigger   string
	Line      int
	Mechanism string
	Target    string
	Kind      Kind
	// TriggerFacts and TargetFacts are the provenance of the two ends. They
	// are zero facts when the collector could not state them.
	TriggerFacts trust.Facts
	TargetFacts  trust.Facts
	// Dynamic is a target the collector could not name statically (a variable
	// command, a PATH lookup). It is reported as coverage, never judged.
	Dynamic bool
}

// rawEdge is an edge before its ends' facts are read.
type rawEdge struct {
	surface        Surface
	reach          Reach
	as             string
	trigger        string
	line           int
	mechanism      string
	target         string
	kind           Kind
	viaInterpreter bool
	dynamic        bool
}
