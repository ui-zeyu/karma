// Package model defines the domain objects: platform, aspect, severity,
// invocation, probe, check, rule, and reading results. Every type depends on
// the standard library only; the check catalog is built in package-level
// variables and stays read-only at runtime.
package model

import (
	"regexp"
	"slices"
	"strings"
	"time"
)

// Platform is the target platform. The second catalog besides Linux is
// Windows user-behavior forensics.
type Platform string

const (
	Linux   Platform = "linux"
	Windows Platform = "windows"
)

// platformOrder is the declaration order of all platforms: the same single
// source as aspectOrder, used for grouping and as the selector vocabulary (a
// platform name selects every check of that platform).
var platformOrder = []Platform{Linux, Windows}

// Aspect is the group a check belongs to; it sets the grouping and order in
// the report.
type Aspect string

const (
	AspectSystem      Aspect = "system"
	AspectIdentity    Aspect = "identity"
	AspectProcess     Aspect = "process"
	AspectNetwork     Aspect = "network"
	AspectService     Aspect = "service"
	AspectPersistence Aspect = "persistence"
	AspectFilesystem  Aspect = "filesystem"
	AspectLog         Aspect = "log"
	AspectKernel      Aspect = "kernel"
	AspectPackage     Aspect = "package"
	AspectExecution   Aspect = "execution"
	AspectDocuments   Aspect = "documents"
	AspectNavigation  Aspect = "navigation"
	AspectRemote      Aspect = "remote"
	AspectDevices     Aspect = "devices"
	AspectTimeline    Aspect = "timeline"
)

// aspectOrder is the declaration order of all aspects; both the catalog
// grouping and the selector vocabulary come from it.
var aspectOrder = []Aspect{
	AspectSystem, AspectIdentity, AspectProcess, AspectNetwork, AspectService,
	AspectPersistence, AspectFilesystem, AspectLog, AspectKernel, AspectPackage,
	AspectExecution, AspectDocuments, AspectNavigation, AspectRemote,
	AspectDevices, AspectTimeline,
}

// enumNames and enumByName turn an enum's declaration order into its name list
// and its name lookup: every vocabulary in this package comes from one of them,
// so the report grouping and the selector accept the same words.
func enumNames[T ~string](values []T) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}

func enumByName[T ~string](values []T) map[string]T {
	out := make(map[string]T, len(values))
	for _, value := range values {
		out[string(value)] = value
	}
	return out
}

var (
	aspectNames     = enumNames(aspectOrder)
	aspectsByName   = enumByName(aspectOrder)
	platformNames   = enumNames(platformOrder)
	platformsByName = enumByName(platformOrder)
)

// AspectNames returns every aspect name in declaration order.
func AspectNames() []string { return slices.Clone(aspectNames) }

// AspectByName resolves an aspect name; ok is false for an unknown name.
func AspectByName(name string) (Aspect, bool) {
	aspect, ok := aspectsByName[name]
	return aspect, ok
}

// PlatformNames returns every platform name in declaration order.
func PlatformNames() []string { return slices.Clone(platformNames) }

// PlatformByName resolves a platform name; ok is false for an unknown name.
func PlatformByName(name string) (Platform, bool) {
	platform, ok := platformsByName[name]
	return platform, ok
}

// Severity is the severity of a hit line. Declaration order is severity order:
// smaller is more severe. "Is this a signal line" is exactly s < Info.
type Severity int

const (
	Critical Severity = iota
	High
	Medium
	Low
	Info
	Benign
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "critical"
	case High:
		return "high"
	case Medium:
		return "medium"
	case Low:
		return "low"
	case Info:
		return "info"
	case Benign:
		return "benign"
	}
	return "unknown"
}

// IsSignal reports whether a line is a finding: it lights up the hit and the
// rail, is always printed, and is exempt from the display budget. benign
// (baseline rows of routine listings) and Info (no hit) are quiet levels.
func (s Severity) IsSignal() bool { return s < Info }

// Outcome is how a check ended: output collected, environment lacked the
// command, or execution failed.
type Outcome int

const (
	Collected Outcome = iota
	Skipped
	Failed
)

// FilterMode is the direction of a line filter: Drop removes matching lines,
// Keep shows only matching lines (allowlist).
type FilterMode int

const (
	FilterDrop FilterMode = iota
	FilterKeep
)

// Invocation is one call that can run on the target. Command goes through exec
// without a shell; Shell is a script that must go through /bin/sh -c (globs,
// redirections, loops). The unexported method seals the implementation set.
type Invocation interface{ isInvocation() }

// Command is an argv call. A nil Requires derives the required binary from
// Argv's first word.
type Command struct{ Argv []string }

// NewCommand builds an argv call; an empty argv fails during catalog
// construction.
func NewCommand(argv ...string) Command {
	if len(argv) == 0 {
		panic("Command.argv must not be empty")
	}
	return Command{Argv: argv}
}

func (Command) isInvocation() {}

// Shell is a script call: handed to /bin/sh -c, requires no binary.
type Shell struct{ Script string }

func (Shell) isInvocation() {}

// RunResult is the result of one call. ExitCode -1 means the call was killed
// on timeout and has no exit code.
type RunResult struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	TimedOut  bool
	Truncated bool
}

// Answered reports whether this tier answered: exit code 0, or stdout already
// has content. Empty stdout still counts as answered.
func (r RunResult) Answered() bool { return r.ExitCode == 0 || strings.TrimSpace(r.Stdout) != "" }

// HostFacts are the target's basic facts, collected in one opening round trip.
type HostFacts struct {
	AvailableBins map[string]bool
	Hostname      string
	Kernel        string
	OsPretty      string
	UID           int
	// Collection identity (USERDOMAIN\user on Windows; empty on Linux because
	// the report header already carries the uid)
	User string
}

// IsRoot reports whether the uid is 0.
func (f HostFacts) IsRoot() bool { return f.UID == 0 }

// HasAll reports whether the capability probe found every wanted binary. An
// empty list is trivially available.
func (f HostFacts) HasAll(wanted []string) bool {
	for _, name := range wanted {
		if !f.AvailableBins[name] {
			return false
		}
	}
	return true
}

// Rule is one highlight rule: text matching pattern is painted.
// Exclude is the line-level exclusion — RE2 has no lookaround, so "does not
// match this prefix/shape" lives in this field; a hit requires Pattern to
// match and the whole line to clear Exclude. Exclusion is line-level because
// the rules that use it match per-path, line-shaped output: one record per
// line.
type Rule struct {
	ID       string
	Pattern  *regexp.Regexp
	Severity Severity
	Message  string
	Exclude  *regexp.Regexp
}

// NewRule compiles the regex and builds a Rule; a bad regex fails during
// catalog construction.
// Case insensitivity is written into the pattern itself ((?i)).
func NewRule(id, pattern string, severity Severity, message string) Rule {
	return Rule{ID: id, Pattern: regexp.MustCompile(pattern), Severity: severity, Message: message}
}

// WithExclude attaches a line-level exclusion and returns a copy.
func (r Rule) WithExclude(exclude string) Rule {
	r.Exclude = regexp.MustCompile(exclude)
	return r
}

// Find returns the first matching span; a line hitting the exclusion does not
// count as a hit.
func (r Rule) Find(line string) (start, end int, ok bool) {
	loc := r.Pattern.FindStringIndex(line)
	if loc == nil {
		return 0, 0, false
	}
	if r.Exclude != nil && r.Exclude.MatchString(line) {
		return 0, 0, false
	}
	return loc[0], loc[1], true
}

// LineFilter is one line filter. Drop: matching lines are not shown; Keep:
// only matching lines are shown (allowlist). Exclude has the same meaning as
// on Rule.
type LineFilter struct {
	ID      string
	Pattern *regexp.Regexp
	Mode    FilterMode
	Exclude *regexp.Regexp
}

// NewFilter compiles the regex and builds a line filter; a bad regex fails
// during catalog construction.
func NewFilter(id, pattern string, mode FilterMode) LineFilter {
	return LineFilter{ID: id, Pattern: regexp.MustCompile(pattern), Mode: mode}
}

// WithExclude attaches a line-level exclusion and returns a copy.
func (f LineFilter) WithExclude(exclude string) LineFilter {
	f.Exclude = regexp.MustCompile(exclude)
	return f
}

// Match reports whether the line is a hit; a line hitting the exclusion does
// not count.
func (f LineFilter) Match(line string) bool {
	if !f.Pattern.MatchString(line) {
		return false
	}
	return f.Exclude == nil || !f.Exclude.MatchString(line)
}

// Match is one hit position plus its conclusion. Regex hits and conclusions
// the normalizer states up front (listing outliers) are both Match: span,
// severity, and reason are fixed where they are produced, and filtering and
// rendering never read the rule back.
type Match struct {
	ID       string
	Severity Severity
	Message  string
	Start    int
	End      int
}

// LineMatch is a span stated by a normalizer: it falls on line Line of the
// body (0-based).
type LineMatch struct {
	Line  int
	Match Match
}

// Shaped is normalized body text plus the spans the normalizer stated up
// front.
type Shaped struct {
	Text  string
	Notes []LineMatch
}

// Normalizer is a pure function over one section body: Probe.Adapt aligns the
// dialect of one tier, Check.Normalize normalizes the body. The first
// parameter is the section title (empty for the preamble section), and
// normalizers that must tell sources apart use it. Returning nil means the
// body is used as is.
type Normalizer func(title string, body string) *Shaped

// Line is one line after folding and before filtering. Number is the line
// number in the whole text; filtered-out lines still consume a number.
type Line struct {
	Number   int
	Text     string
	Severity Severity
	Matches  []Match
}

// Section is one file or one preamble. An empty Title is the body before the
// first section marker.
type Section struct {
	Title        string
	TitleMatches []Match
	Lines        []Line
}

// Document is the reading result of one text. Filtered is a sequence of
// (filter id, hit count).
type Document struct {
	Sections  []Section
	Truncated bool
	Filtered  []FilterCount
}

// FilterCount is the number of lines one filter hid.
type FilterCount struct {
	ID    string
	Count int
}

// Probe is one tier. A nil Requires derives from the invocation (Command
// takes Argv's first word, Shell is the empty set); Adapt only turns this
// tier's output into the same shape as the other tiers and runs within the
// section; normalization that must run whichever tier wins hangs on
// Check.Normalize.
type Probe struct {
	Label     string
	Inv       Invocation
	Requires  []string
	Adapt     Normalizer
	LineLimit int // line limit for open scans, 0 for none
	Head      int // the row shape this tier wants, 0 for none
}

// RequiredBins is the binary names this tier requires. With a nil Requires it
// derives from Command's argv[0]; the returned slice is new, so the caller's
// appends never write through Argv.
func (p Probe) RequiredBins() []string {
	if p.Requires != nil {
		return p.Requires
	}
	if cmd, ok := p.Inv.(Command); ok && len(cmd.Argv) > 0 {
		return []string{cmd.Argv[0]}
	}
	return nil
}

// Check is one check: its fallback chain, its already-composed filters and
// rules, and an optional body normalizer.
type Check struct {
	ID        string
	Title     string
	Aspect    Aspect
	Platform  Platform // catalog platform: the list group banner and the platform selector
	Probes    []Probe
	Filters   []LineFilter
	Rules     []Rule
	Timeout   time.Duration // 0 means the global timeout from the run options
	Syntax    string        // syntax declaration for the presentation layer; empty for none
	Normalize Normalizer    // normalizes the winning body per section; the section title is passed and only dialect alignment (Probe.Adapt) reads it
	ScanBytes int           // 0 means the default read cap, reader.MaxScanBytes
}

// CheckResult is the outcome of one check. Outcome separates "not collected"
// (missing command, environment fact) from "failed" (execution error, signal);
// document decides visibility on its own, so the presentation layer needs
// nothing else. Raw is the channel's stdout exactly as collected — the
// evidence --save writes, before the reading layer caps or shapes anything.
// Document is the reading result, computed once when the report is built, and
// the presentation layer only reads it.
type CheckResult struct {
	Check         *Check
	ProbeLabel    string
	Outcome       Outcome
	SkippedLabels []string
	Raw           string
	Stderr        string
	Note          string
	Document      Document
}

// Run defaults, shared by the CLI options and RunOptions.
const (
	DefaultConcurrency = 6
	DefaultTimeout     = 30 * time.Second
	DefaultMaxLines    = 400
)

// RunOptions holds the run options shared by local and ssh.
type RunOptions struct {
	Selectors   []string
	Concurrency int
	Timeout     time.Duration
	MaxLines    int
	// SaveDir is the evidence directory; an empty string saves nothing. The
	// channel's raw output is written per file as <aspect>/<check id>.txt.
	SaveDir string
}
