// Package audit is the detection model: it reads an artifact boundary from the
// target, collects the objects that can decide a future execution, and judges
// the delta by the authority it can reach.
package audit

import (
	"context"
	"time"

	"karma/internal/prov"
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
	Hostname string `json:"hostname"`
	Kernel   string `json:"kernel"`
	OS       string `json:"os"`
	UID      int    `json:"uid"`
}

// Process is one running principal: the image, the script an interpreter
// carries, and the account the kernel gave it. Root is the process's root
// link, which differs from / on a chroot; Outbound counts its established
// connections.
type Process struct {
	PID  int `json:"pid"`
	PPID int `json:"ppid"`
	UID  int `json:"uid"`
	GID  int `json:"gid"`
	// EUID and EGID are the effective ids the kernel enforces. A setuid
	// process runs with these, so reach follows them and not the real id.
	EUID    int    `json:"euid"`
	EGID    int    `json:"egid"`
	Start   uint64 `json:"start"`
	State   string `json:"state,omitempty"`
	Comm    string `json:"comm,omitempty"`
	Exe     string `json:"exe,omitempty"`
	Cmdline string `json:"cmdline,omitempty"`
	Cwd     string `json:"cwd,omitempty"`
	Root    string `json:"root,omitempty"`
	Script  string `json:"script,omitempty"`
	// Cgroup is the process's cgroup path; Unit is the systemd unit named by
	// it. The object graph uses the edge from a unit to its live processes.
	Cgroup string `json:"cgroup,omitempty"`
	Unit   string `json:"unit,omitempty"`
	// LoaderTargets are the libraries LD_PRELOAD/LD_AUDIT named, and
	// LibraryPath is the raw LD_LIBRARY_PATH value.
	LoaderTargets []LoaderTarget `json:"loader_targets,omitempty"`
	LibraryPath   string         `json:"library_path,omitempty"`
	// CapEff is the effective capability mask, Seccomp the filter mode, and
	// NoNewPrivs the prctl bit; together they state what the process can do
	// beyond its uid.
	CapEff      uint64      `json:"cap_eff,omitempty"`
	Seccomp     int         `json:"seccomp,omitempty"`
	NoNewPrivs  bool        `json:"no_new_privs,omitempty"`
	Outbound    int         `json:"outbound,omitempty"`
	ExeFacts    trust.Facts `json:"-"`
	ScriptFacts trust.Facts `json:"-"`
	Deleted     bool        `json:"deleted,omitempty"`
}

// LoaderTarget is one library a dynamic-loader variable names. Variable is
// LD_PRELOAD or LD_AUDIT; a soname remains a lead with no facts.
type LoaderTarget struct {
	Variable string      `json:"variable"`
	Path     string      `json:"path,omitempty"`
	Facts    trust.Facts `json:"-"`
}

// Connection is one established TCP connection. It is kept apart from the
// listening socket table: a listener is a service surface, a connection is a
// live relationship between a process and a peer.
type Connection struct {
	Proto string `json:"proto"`
	Local string `json:"local"`
	Peer  string `json:"peer"`
	PID   int    `json:"pid,omitempty"`
	Comm  string `json:"comm,omitempty"`
	// PIDs are every process holding the socket. A shell that spawns a child
	// with the fd still open is the common reverse-shell shape.
	PIDs []int `json:"pids,omitempty"`
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

// Snapshot is the facts one local collection answered.
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
	ledgerRows []ledgerFile
	catalog    *prov.Catalog
	Unreadable []string
	Coverage   []string
	Source     string
	// Unowned is the static inventory's dormant executables: files in the
	// program directories no package's file list records.
	Unowned []UnownedFile
	// Kernel is the runtime kernel state: loaded modules, the registries that
	// disagree about them, the taint mask, hidden pids, and the dynamic
	// loader's search path.
	Kernel KernelState
	// Connections are the established TCP relationships, the peer side of
	// the listener table.
	Connections []Connection
	// Packages is the package-file provenance sweep.
	Packages PackageState
	// Identity is the parsed account/sudo/sshd graph.
	Identity IdentityState
	// Web is the web-root script provenance sweep.
	Web WebState
	// Clock is the boundary-integrity reading.
	Clock ClockState

	// plan is the selection this snapshot was collected under. The module
	// collectors read its scoping fields.
	plan Plan
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

// ensureFacts reads paths the object graph discovered after collection. Package
// ownership is answered in one batch before the facts are read, so a tree of
// discovered files costs one package-manager call rather than one per file.
func (s *Snapshot) ensureFacts(paths []string) {
	if s.Objects == nil {
		s.Objects = map[string]trust.Facts{}
	}
	seen := make(map[string]bool, len(paths))
	var missing []string
	for _, path := range paths {
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		if _, ok := s.Objects[path]; !ok {
			missing = append(missing, path)
		}
	}
	if len(missing) == 0 {
		return
	}
	s.ownedAll(missing)
	for _, path := range missing {
		s.Objects[path] = s.classify(path)
	}
}

// Quote is one source line a finding rests on: the file, its 1-based
// line, and the text as read.
type Quote struct {
	Path string `json:"path"`
	Line int    `json:"line,omitempty"`
	Text string `json:"text"`
}

// Finding is one judged relation. Path is the object the operator should look
// at; Detail names what it activates or what activates it.
type Finding struct {
	Class string
	// Domain is the bounded domain the class belongs to; a graph command
	// selects findings by it, so a class never needs a second vocabulary.
	Domain   Domain
	Severity Severity
	Title    string
	Path     string
	Origin   Origin
	Reach    Reach
	Detail   string
	Evidence []string
	// Quotes are the source lines behind the finding: the file text a
	// reader can check, not a restatement of the evidence.
	Quotes []Quote
	// Trace is the relation path that produced the finding: account deploy →
	// group docker → sudo NOPASSWD. Each step can name the graph node it
	// speaks for, so a finding and a graph cannot drift apart.
	Trace []Step
}

// Step is one hop in a finding's relation path. Node is the graph node id the
// hop speaks for, empty when the step names an abstract edge.
type Step struct {
	Text string
	Node string
}

// traceTexts reads a trace as the display line the report prints.
func traceTexts(trace []Step) []string {
	if len(trace) == 0 {
		return nil
	}
	texts := make([]string, 0, len(trace))
	for _, step := range trace {
		texts = append(texts, step.Text)
	}
	return texts
}

// traceNodes reads a trace's node ids.
func traceNodes(trace []Step) []string {
	var nodes []string
	for _, step := range trace {
		if step.Node != "" {
			nodes = append(nodes, step.Node)
		}
	}
	return nodes
}

// Report is the audit's answer, and the document both the text renderer and
// the JSON encoder are built from: findings, the raw inventories behind them,
// and the coverage that says how far the evidence reached.
type Report struct {
	Boundary    Boundary
	Host        Host
	Source      string
	Findings    []Finding
	Coverage    []string
	Activated   int
	Processes   int
	Authority   int
	Services    []Service
	Sockets     []Socket
	Connections []Connection
	Mounts      []Mount
	Ledger      LedgerSummary
	// Kernel is set when the run collected the kernel domain.
	Kernel *KernelState
	// OffDomains names the bounded domains a scoped run did not judge; empty
	// on a bare run, where every domain answered.
	OffDomains []string
	// The raw inventories the evidence panels print. They are the collected
	// rows, not a second judgment: the panels re-read origins through the
	// report's own verdicts.
	Activations      []startup.Edge
	ProcessRows      []Process
	AuthorityObjects []string
	Unowned          []UnownedFile

	// view is the inventories the scope filtered once; the evidence panels
	// read it instead of re-filtering the collected rows.
	view *View
}

// ownedAll prefills the package answers for paths; the catalog answers from
// its own index, a test-built resolver from its cache.
func (s *Snapshot) ownedAll(paths []string) {
	if s == nil || s.catalog == nil {
		return
	}
	s.catalog.OwnedAll(paths)
}

// classify reads one path's facts through the run's package catalog.
func (s *Snapshot) classify(path string) trust.Facts {
	if s == nil {
		return trust.Classify(path, nil)
	}
	return trust.Classify(path, s.catalog)
}

// Filter narrows an audit without changing its judgments.
type Filter struct {
	Surfaces     map[string]bool // canonical surface names; nil means all
	Paths        []string
	ExcludePaths []string
	PIDs         map[int]bool
	Units        map[string]bool // systemd units a service run is narrowed to
	MinSeverity  Severity
	// OffDomains names the bounded domains this run did not judge, so the
	// report can say what its quiet covers.
	OffDomains []string
}

// narrowed reports whether the filter selects less than the whole bounded
// host: a scope word, a path, pid, unit or a domain left unjudged.
func (f Filter) narrowed() bool {
	return f.Surfaces != nil || len(f.Paths)+len(f.ExcludePaths)+len(f.PIDs)+len(f.Units) > 0 ||
		len(f.OffDomains) > 0
}

// Progress reports the collection stage a run entered. The stage words are
// "catalog" (the package database), "startup" (the activation surfaces), the
// registry's domain words in collection order, and "ledger" (the content
// hashing). CollectLocal calls it from the collecting goroutine before each
// stage; a run without a reporter passes nil.
type Progress func(stage string)

// CollectLocal reads the domains the plan selected in process.
func CollectLocal(ctx context.Context, plan Plan, progress Progress) (*Snapshot, error) {
	return collectLocal(ctx, plan, progress)
}

// SetBoundary replaces the artifact edge after collection (--since) and
// re-dates the ledger rows against it, so the tamper set follows the edge the
// operator asked for.
func (s *Snapshot) SetBoundary(boundary Boundary) {
	if s == nil {
		return
	}
	s.Boundary = boundary
	s.tamper = ledgerTamper(s.Boundary, s.PackageTimes, s.ledgerRows)
	s.Ledger.Tampered = tamperedPackages(s.tamper)
}
