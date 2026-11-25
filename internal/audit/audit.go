// Package audit is the detection model: it reads an artifact boundary from the
// target, collects the objects that can decide a future execution, and judges
// the delta by the authority it can reach.
package audit

import (
	"context"
	"time"

	"karma/internal/startup"
	"karma/internal/trust"
)

// Origin is where an object came from: the artifact, a declared producer, or
// the running system.
type Origin uint8

const (
	Unknown Origin = iota
	Runtime
	PreExisting
	Modified
	Provisioned
	Base
)

var originNames = [...]string{"unknown", "runtime", "preexisting", "modified", "provisioned", "base"}

func (o Origin) String() string {
	if int(o) >= len(originNames) {
		return "unknown"
	}
	return originNames[o]
}

// Rank orders origins by integrity, worst first. The judge reads it to pick
// the weaker end of a relation.
func (o Origin) Rank() int { return int(o) }

// Severity is the finding's priority, derived from reachable authority.
type Severity uint8

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if int(s) >= len(severityNames) {
		return "info"
	}
	return severityNames[s]
}

// ParseSeverity reads the flag's word.
func ParseSeverity(name string) (Severity, bool) {
	for index, value := range severityNames {
		if value == name {
			return Severity(index), true
		}
	}
	return Info, false
}

// Reach is the authority an object can acquire: the account it runs as and
// what the kernel grants it.
type Reach uint8

const (
	NoAsset Reach = iota
	UserAsset
	ServiceAsset
	RootAsset
	KernelAsset
)

var reachNames = [...]string{"none", "user", "service", "root", "kernel"}

func (r Reach) String() string {
	if int(r) >= len(reachNames) {
		return "none"
	}
	return reachNames[r]
}

// Confidence is how much the observation supports the finding.
type Confidence uint8

const (
	LowConfidence Confidence = iota
	MediumConfidence
	HighConfidence
)

var confidenceNames = [...]string{"low", "medium", "high"}

func (c Confidence) String() string {
	if int(c) >= len(confidenceNames) {
		return "low"
	}
	return confidenceNames[c]
}

// Boundary is the artifact's edge in time: objects older than it came with the
// target, objects newer arrived later.
type Boundary struct {
	Time       time.Time
	Kind       string // container, host, snapshot
	Source     string // pid1, boot, package, operator, none
	Confidence Confidence
}

// Host is the target's identity, enough to read the report without context.
type Host struct {
	Hostname string
	Kernel   string
	OS       string
	UID      int
}

// Process is one running principal: the image, the script an interpreter
// carries, and the account the kernel gave it. Root is the process's root
// link, which differs from / on a chroot; Outbound counts its established
// connections.
type Process struct {
	PID         int
	PPID        int
	UID         int
	GID         int
	Start       uint64
	State       string
	Comm        string
	Exe         string
	Cmdline     string
	Cwd         string
	Root        string
	Script      string
	Outbound    int
	ExeFacts    trust.Facts
	ScriptFacts trust.Facts
	Deleted     bool
}

// Service is one unit systemd reports: the raw inventory behind the activation
// edges, including services whose unit file the collector did not read.
type Service struct {
	Unit        string `json:"unit"`
	Load        string `json:"load"`
	Active      string `json:"active"`
	Sub         string `json:"sub"`
	Description string `json:"description,omitempty"`
}

// Socket is one listening socket: the raw network surface behind the process
// table. A socket without an owner is still listed; pid 0 means no local owner
// was visible.
type Socket struct {
	Proto string `json:"proto"`
	State string `json:"state"`
	Local string `json:"local"`
	Peer  string `json:"peer"`
	PID   int    `json:"pid,omitempty"`
	Comm  string `json:"comm,omitempty"`
}

// Snapshot is the collected facts one source answered. Both the native and the
// sh source produce this same shape.
type Snapshot struct {
	Boundary    Boundary
	Host        Host
	Activations []startup.Edge
	Processes   []Process
	Services    []Service
	Sockets     []Socket
	Authority   []string
	Objects     map[string]trust.Facts
	// PackageTimes dates the last transaction per package, so a file installed
	// after the boundary reads as provisioned rather than runtime.
	PackageTimes map[string]time.Time
	// Verify carries the content ledger's answer per resolved path, Mounts the
	// mount table, and Ledger which content ledger the run used. conffiles,
	// tamper and ownerOf are the ledger's own records the judge reads.
	Verify     map[string]Content
	Mounts     []Mount
	Ledger     LedgerSummary
	conffiles  map[string]bool
	tamper     []ledgerFile
	ownerOf    map[string]string
	Unreadable []string
	Coverage   []string
	Source     string
}

// Facts returns the collected facts for path, or zero facts.
func (s *Snapshot) Facts(path string) trust.Facts {
	if s == nil || path == "" {
		return trust.Facts{}
	}
	if facts, ok := s.Objects[path]; ok {
		return facts
	}
	return trust.Facts{Path: path, Kind: trust.Missing, Owner: -1, Group: -1}
}

// Finding is one judged relation. Path is the object the operator should look
// at; Detail names what it activates or what activates it.
type Finding struct {
	Class    string
	Severity Severity
	Title    string
	Path     string
	Origin   Origin
	Reach    Reach
	Detail   string
	Evidence []string
}

// Report is the audit's answer.
type Report struct {
	Boundary  Boundary
	Host      Host
	Source    string
	Findings  []Finding
	Coverage  []string
	Activated int
	Processes int
	Authority int
	Services  []Service
	Sockets   []Socket
	Mounts    []Mount
	Ledger    LedgerSummary
}

// Filter narrows an audit without changing its judgments.
type Filter struct {
	Surfaces     map[string]bool // canonical surface names; nil means all
	Paths        []string
	ExcludePaths []string
	PIDs         map[int]bool
	MinSeverity  Severity
}

// Exec runs one shell script on a remote target and answers its stdout.
type Exec func(ctx context.Context, script string) (string, error)

// CollectLocal reads the target in process.
func CollectLocal(ctx context.Context) (*Snapshot, error) {
	return collectLocal(ctx)
}

// CollectRemote reads the target through one executor.
func CollectRemote(ctx context.Context, exec Exec) (*Snapshot, error) {
	return collectRemote(ctx, exec)
}
