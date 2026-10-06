// Package model defines the domain objects: platform, aspect, severity,
// invocation, probe, check, rule, and reading results. Every type depends on
// the standard library only; the check catalog is built in package-level
// variables and stays read-only at runtime.
package model

import (
	"context"
	"errors"
	"regexp"
	"slices"
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

// Syntax is the presentation layer's lexer declaration for a check's body
// lines: the pseudo-lexer, or the chroma lexer, that colors its rows. It is a
// vocabulary like Aspect, so a catalog names one only through the constants
// below and a misspelling is a compile error rather than a panel that silently
// loses its color. The empty syntax declares none; the presentation layer's
// lexer table is checked against every syntax the catalog declares.
type Syntax string

const (
	SyntaxLsL        Syntax = "ls-l"
	SyntaxEnv        Syntax = "env"
	SyntaxDmesg      Syntax = "dmesg"
	SyntaxSshdConfig Syntax = "sshd-config"
	SyntaxSSHPubkey  Syntax = "ssh-pubkey"
	SyntaxColon      Syntax = "colon"
	SyntaxLsmod      Syntax = "lsmod"
	SyntaxIPAddr     Syntax = "ip-addr"
	SyntaxTable      Syntax = "table"
	SyntaxTop        Syntax = "top"
	SyntaxDf         Syntax = "df"
	SyntaxLastlog    Syntax = "lastlog"
	SyntaxUnits      Syntax = "units"
	SyntaxListen     Syntax = "listen"
	SyntaxNetstat    Syntax = "netstat"
	SyntaxIPKeyval   Syntax = "ip-keyval"
	SyntaxPkgHistory Syntax = "pkg-history"
	SyntaxFstab      Syntax = "fstab"
	SyntaxReg        Syntax = "reg"
	SyntaxPipe       Syntax = "pipe"
	SyntaxPowerShell Syntax = "powershell"
	SyntaxBash       Syntax = "bash"
)

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

// severityNames is the name of each severity, in the Severity declaration
// order; the name lookup and the flag vocabularies read it, so a level is named
// once. A test pins its length against the last constant.
var severityNames = []string{"critical", "high", "medium", "low", "info", "benign"}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return "unknown"
	}
	return severityNames[s]
}

// SeverityByName resolves a severity name; ok is false for an unknown name.
func SeverityByName(name string) (Severity, bool) {
	if index := slices.Index(severityNames, name); index >= 0 {
		return Severity(index), true
	}
	return 0, false
}

// SeverityNames returns every severity name in declaration order; the selector
// and flag vocabularies and their messages read it.
func SeverityNames() []string { return slices.Clone(severityNames) }

// IsSignal reports whether a line is a finding: it lights up the hit and the
// rail, is always printed, and is exempt from the display budget. benign
// (baseline rows of routine listings) and Info (no hit) are quiet levels.
func (s Severity) IsSignal() bool { return s < Info }

// SeverityFloor is how much of a report a run keeps: a row below the floor is
// counted like a filtered line and left out of the document. The value is one
// past the least severe level it keeps, which is what makes the zero value mean
// "no floor" — an unset run option has to show the whole report — while a level
// still names itself through FloorAbove.
type SeverityFloor Severity

// FloorAll keeps every row, the quiet baseline levels included. It is the zero
// value, and the run option's default.
const FloorAll SeverityFloor = 0

// FloorAbove is the floor that keeps level and every more severe level.
func FloorAbove(level Severity) SeverityFloor { return SeverityFloor(level) + 1 }

// Keeps reports whether a row at this severity is at or above the floor.
func (f SeverityFloor) Keeps(severity Severity) bool {
	return f == FloorAll || severity < Severity(f)
}

// String names the least severe level the floor keeps, or "all" for the floor
// that keeps every row.
func (f SeverityFloor) String() string {
	if f == FloorAll {
		return "all"
	}
	return Severity(f - 1).String()
}

// ParseSeverityFloor resolves a --min-severity word: "all" keeps the whole
// report, and a level name keeps that level and every more severe one.
func ParseSeverityFloor(name string) (SeverityFloor, bool) {
	if name == "all" {
		return FloorAll, true
	}
	level, ok := SeverityByName(name)
	if !ok {
		return FloorAll, false
	}
	return FloorAbove(level), true
}

// Outcome is how a check's walk ended. A tier that failed mid-walk is still
// Collected — its error text is the note the panel shows — so the other two
// values are the ones that say the walk did not run.
type Outcome int

const (
	// Collected: the walk ran. A tier that answered with an empty body and one
	// whose failure left only stderr are both this; the note carries which.
	Collected Outcome = iota
	// Skipped: every tier was unavailable here — the target's environment lacks
	// the command.
	Skipped
	// Failed: karma's own boundary broke this check, so the walk produced
	// nothing at all.
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
// redirections, loops); Dual pairs a per-channel implementation of one tier.
// The unexported method seals the implementation set.
type Invocation interface{ isInvocation() }

// Command is an argv call; the required binary is Argv's first word.
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

// Dual is one tier with a per-channel implementation: Run is the in-process
// body for the channel where karma itself runs on the target, Script is the
// /bin/sh body for every remote channel (ssh, ttyd). A zero field means the
// tier exists on the other channel only. Both branches print the same shape,
// so rules, filters, and lexers apply unchanged, and each branch decides its
// own availability — Run answers model.ErrTierUnavailable, the script answers
// 127 — so the chain falls to the next tier within the channel.
type Dual struct {
	Run    func(ctx context.Context) (string, error) // local channel, in process
	Script string                                    // remote channels, /bin/sh -c
}

func (Dual) isInvocation() {}

// For returns the invocation one channel executes: the Dual itself on a
// channel it exists for, nil when this tier does not exist there.
func (d Dual) For(ch Channel) Invocation {
	if (ch == ChanLocal && d.Run != nil) || (ch.Remote() && d.Script != "") {
		return d
	}
	return nil
}

// ErrTierUnavailable marks a Dual.Run call that cannot run in this environment
// (wrong platform, no /proc): the session reports it like a missing binary
// (exit 127) so the probe chain falls to the next tier.
var ErrTierUnavailable = errors.New("native tier unavailable in this environment")

// Verdict is how one call ended, as the channel could tell. It is what the
// fallback chain reads: a tier that settled the question ends the walk (an
// answer, or a cut whose partial output is kept), and an unavailable or failed
// tier leaves the walk going. The channel boundary states it, so no caller has
// to know the exit codes' conventions.
type Verdict int8

const (
	// VerdictFailed: the call produced no answer — the channel broke, or the
	// command exited non-zero with nothing on stdout. Stderr is what a panel
	// then names.
	VerdictFailed Verdict = iota
	// VerdictAnswered: stdout is this tier's answer, the exit code and all. An
	// empty stdout is an answer too (a verifier with nothing to report).
	VerdictAnswered
	// VerdictUnavailable: the environment lacks this tier — a binary the shell's
	// own guard reported missing (127), or an in-process body that cannot run
	// here. The chain falls to the next tier.
	VerdictUnavailable
	// VerdictTimedOut: the deadline stopped the source. The output already
	// produced is kept and the chain does not advance.
	VerdictTimedOut
	// VerdictInterrupted: cancellation (Ctrl-C) stopped the source, which keeps
	// the output it had produced. The chain does not advance.
	VerdictInterrupted
)

// Settled reports whether this tier ended the walk: it answered, or it was cut
// short and its partial output is what stays. A failed or unavailable tier
// leaves the chain walking.
func (v Verdict) Settled() bool {
	return v == VerdictAnswered || v == VerdictTimedOut || v == VerdictInterrupted
}

// Cut reports whether the call was stopped mid-flight by the deadline or by
// cancellation, with the output it had produced kept.
func (v Verdict) Cut() bool { return v == VerdictTimedOut || v == VerdictInterrupted }

// String names the verdict, for the messages that report a call that did not
// answer.
func (v Verdict) String() string {
	switch v {
	case VerdictAnswered:
		return "answered"
	case VerdictUnavailable:
		return "unavailable"
	case VerdictTimedOut:
		return "timed out"
	case VerdictInterrupted:
		return "interrupted"
	}
	return "failed"
}

// RunResult is the result of one call.
type RunResult struct {
	Verdict Verdict
	Stdout  string
	Stderr  string
	// ExitCode is the process's status; -1 when the call has none (a cut call,
	// or a channel that could not say).
	ExitCode int
	// Truncated marks a body a cap stopped: the source did not finish on its
	// own. Whether the panel reports that is the tier's row cap's decision.
	Truncated bool
}

// RowCap is a tier's row cap: how many rows the tier wants, and what reaching
// the cap means. The zero value is no cap.
type RowCap struct {
	// Rows is the row count the cap allows; 0 is no cap.
	Rows int
	// Answer marks a cap that is the tier's own answer: a sorted view's top N is
	// complete at the cap, so the panel is not told the body was cut. A scan cap
	// bounds an open walk and is presented as a cut.
	Answer bool
}

// Shape is the cap of a tier whose answer is a fixed number of rows: a listing
// head, or a sorted view's top N.
func Shape(rows int) RowCap { return RowCap{Rows: rows, Answer: true} }

// Scan is the cap that bounds an open scan, like `find ... | head`: reaching it
// is a cut, and the panel reports the body as truncated.
func Scan(rows int) RowCap { return RowCap{Rows: rows} }

// Cut reports whether a body this cap stopped is presented as cut. The byte
// safety valve's cut is a cut either way; this is only about the tier's own cap.
func (c RowCap) Cut() bool { return c.Rows > 0 && !c.Answer }

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
	// ProbeCut marks a capability probe cut short by its deadline: every name
	// it did not reach reads as missing, so the checks needing it report
	// skipped rather than failed — the run owes the operator that explanation.
	ProbeCut bool
}

// IsRoot reports whether the uid is 0.
func (f HostFacts) IsRoot() bool { return f.UID == 0 }

// Has reports whether the capability probe found one binary.
func (f HostFacts) Has(name string) bool { return f.AvailableBins[name] }

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
	// literals is the prefilter of Pattern (see prefilter.go): the strings a
	// line must contain for Pattern to match it, empty when none could be
	// proven. It is derived here so no caller can forget it.
	literals []string
}

// NewRule compiles the regex and builds a Rule; a bad regex fails during
// catalog construction.
// Case insensitivity is written into the pattern itself ((?i)).
func NewRule(id, pattern string, severity Severity, message string) Rule {
	return Rule{
		ID:       id,
		Pattern:  regexp.MustCompile(pattern),
		Severity: severity,
		Message:  message,
		literals: prefilter(pattern),
	}
}

// WithExclude attaches a line-level exclusion and returns a copy.
func (r Rule) WithExclude(exclude string) Rule {
	r.Exclude = regexp.MustCompile(exclude)
	return r
}

// Find returns the first matching span; a line hitting the exclusion does not
// count as a hit, and a line missing the pattern's prefilter literals is not
// run through the engine at all.
func (r Rule) Find(line string) (start, end int, ok bool) {
	if !prefilterMatches(r.literals, line) {
		return 0, 0, false
	}
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
	// literals is Pattern's prefilter, as on Rule.
	literals []string
}

// NewFilter compiles the regex and builds a line filter; a bad regex fails
// during catalog construction.
func NewFilter(id, pattern string, mode FilterMode) LineFilter {
	return LineFilter{
		ID:       id,
		Pattern:  regexp.MustCompile(pattern),
		Mode:     mode,
		literals: prefilter(pattern),
	}
}

// WithExclude attaches a line-level exclusion and returns a copy.
func (f LineFilter) WithExclude(exclude string) LineFilter {
	f.Exclude = regexp.MustCompile(exclude)
	return f
}

// Match reports whether the line is a hit; a line hitting the exclusion does
// not count, and a line missing the pattern's prefilter literals is not run
// through the engine at all.
func (f LineFilter) Match(line string) bool {
	if !prefilterMatches(f.literals, line) {
		return false
	}
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

// Channel is which side of the wire karma itself runs on. The session answers
// with the channel it is (ChanLocal, ChanSSH, ChanTTYD); the runner resolves
// each probe against that answer while walking the chain.
type Channel int8

const (
	// ChanLocal: karma itself runs on the collected host.
	ChanLocal Channel = iota + 1
	// ChanSSH: the target is reached over ssh.
	ChanSSH
	// ChanTTYD: the target is reached through a ttyd web terminal's websocket.
	ChanTTYD
)

// Remote reports whether the channel reaches the target from outside: every
// channel but local executes a Dual's script side, so a new remote channel
// cannot silently end up with an empty chain.
func (c Channel) Remote() bool { return c != ChanLocal }

// Call is one call to run on the target: what to run, and how much of the
// output this tier wants. The deadline is not here because it is not a
// property of one call: it travels in the context, established by the caller
// that owns the policy — the runner gives one check's whole walk a single
// deadline (session.Within) — so every layer of the call answers to the same
// one, and the channel's own setup is covered by it too.
type Call struct {
	Inv Invocation
	Cap RowCap
}

// Probe is one tier. A nil Requires derives from the invocation (Command
// takes Argv's first word); Adapt only turns this tier's output into the same
// shape as the other tiers and runs within the section; normalization that
// must run whichever tier wins hangs on Check.Normalize.
type Probe struct {
	Label string
	Inv   Invocation
	Adapt Normalizer
	Cap   RowCap
}

// Step is one step of a check's walk: the probes that answer as a whole. One
// probe is the common step. Several are the source that needs one process per
// item — a PS-less Windows target runs one reg.exe per key because the local
// channel has no shell to loop in — where the step answers when any member
// answered and the bodies join in declaration order. Declaring them as
// alternatives to one another would let the walk stop at the first key that
// exists and silently drop the rest of the evidence.
type Step []Probe

// InvocationFor returns the invocation one channel executes for this tier:
// nil when the tier does not exist on that channel (a Dual with only the
// other side set). The runner skips such a tier silently — it is not part of
// that channel's chain.
func (p Probe) InvocationFor(ch Channel) Invocation {
	if d, ok := p.Inv.(Dual); ok {
		return d.For(ch)
	}
	return p.Inv
}

// RequiredBin is the one binary this tier requires, empty when it requires none:
// the Command's argv[0]. Scripts and in-process tiers decide availability
// themselves at run time (a guard in the script, ErrTierUnavailable in the
// function).
func (p Probe) RequiredBin() string {
	if cmd, ok := p.Inv.(Command); ok && len(cmd.Argv) > 0 {
		return cmd.Argv[0]
	}
	return ""
}

// Check is one check: its fallback walk, its already-composed filters and
// rules, and an optional body normalizer.
type Check struct {
	ID       string
	Title    string
	Aspect   Aspect
	Platform Platform // catalog platform: the list group banner and the platform selector
	Steps    []Step   // the walk: one step per tier or group of tiers that answer together
	Filters  []LineFilter
	Rules    []Rule
	// Timeout is this check's own budget, overriding the run option; 0 means the
	// run's. It bounds the whole walk (runner.runCheck), not one tier's call.
	Timeout   time.Duration
	Syntax    Syntax     // syntax declaration for the presentation layer; empty for none
	Normalize Normalizer // normalizes the winning body per section; the section title is passed and only dialect alignment (Probe.Adapt) reads it
	ScanBytes int        // 0 means the default read cap, reader.MaxScanBytes
	// SectionSyntax overrides Syntax per section: the first entry whose Title
	// glob (path.Match) matches the section title wins, other sections keep
	// Syntax. A section usually carries one source's shape, so mixed-output
	// checks (a listing followed by the files' contents) declare one override
	// per shape instead of one combined lexer.
	SectionSyntax []SectionSyntax
}

// SectionSyntax is one title-syntax override of Check.Syntax.
type SectionSyntax struct {
	Title  string // glob against the section title (path.Match)
	Syntax Syntax
}

// CheckResult is the outcome of one check. Outcome and Note together say what
// happened to the walk; document decides visibility on its own, so the
// presentation layer reads the outcome only to tell a skipped check from a
// collected one. Raw is the channel's stdout exactly as collected — the
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
	// MinSeverity is how much of the reading each check keeps: rows below the
	// floor are counted like filtered lines and left out of its document, so a
	// triage run can drop everything under one level. It filters what is shown,
	// never what is saved: SaveDir writes the channel's raw text.
	MinSeverity SeverityFloor
	// SaveDir is the evidence directory; an empty string saves nothing. The
	// channel's raw output is written per file as <aspect>/<check id>.txt.
	SaveDir string
}
