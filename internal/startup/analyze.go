package startup

import (
	"context"
	"path/filepath"
	"sort"
	"strings"

	"karma/internal/trust"
)

// Dialect is how a collected file is read.
type Dialect uint8

const (
	UnitDialect Dialect = iota
	ShellDialect
	EnvDialect
	CronDialect
	LoaderDialect
	UdevDialect
	AuthorizedKeysDialect
	SSHConfigDialect
	PAMDialect
	AptDialect
	ModprobeDialect
	GeneratorsDialect
	XinetdDialect
	SystemDialect
)

// File is one startup surface file the collector read. Unit names the systemd
// unit a unit file or drop-in belongs to; DropIn marks the second kind, whose
// values override the unit's own.
type File struct {
	Path    string
	Unit    string
	DropIn  bool
	Surface Surface
	Dialect Dialect
	Body    string
}

// FactSource reads one path's provenance. The native source classifies the
// host in process.
type FactSource func(path string) trust.Facts

// Corpus is what both sources hand the analysis: the files the surfaces hold,
// the units that are enabled, and a fact source for the paths the files name.
type Corpus struct {
	ctx        context.Context
	fs         FS
	files      []File
	enabled    map[string]string
	facts      FactSource
	prefetch   func([]string)
	seen       map[string]bool
	unreadable map[string]bool
	masked     map[string]bool
	gaps       map[string]bool
}

// NewCorpus builds a corpus from a source's collection. The enabled map is
// keyed by unit name and states the link that enables it.
func NewCorpus(files []File, enabled map[string]string, facts FactSource) *Corpus {
	if enabled == nil {
		enabled = map[string]string{}
	}
	return &Corpus{
		files: files, enabled: enabled, facts: facts,
		seen: map[string]bool{}, unreadable: map[string]bool{}, masked: map[string]bool{},
		gaps: map[string]bool{},
	}
}

// addGap states an object the analysis named but the disk cannot answer for.
// The audit reports these as coverage.
func (c *Corpus) addGap(line string) { c.gaps[line] = true }

// stopped reports whether the run's context already asked collection to stop;
// a corpus assembled without one never stops.
func (c *Corpus) stopped() bool { return c.ctx != nil && c.ctx.Err() != nil }

// Gaps lists the coverage lines the analysis produced, sorted.
func (c *Corpus) Gaps() []string {
	if c == nil || len(c.gaps) == 0 {
		return nil
	}
	lines := make([]string, 0, len(c.gaps))
	for line := range c.gaps {
		lines = append(lines, line)
	}
	sort.Strings(lines)
	return lines
}

// Unreadable lists the startup files the collector found but could not read,
// sorted. The audit states them as coverage; an unreadable trigger is a gap,
// not an edge.
func (c *Corpus) Unreadable() []string {
	if c == nil || len(c.unreadable) == 0 {
		return nil
	}
	paths := make([]string, 0, len(c.unreadable))
	for path := range c.unreadable {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

// Prefetch lets the native source fill its package cache for the targets the
// parse is about to judge, one database call instead of one per path. The sh
// source already carries every fact and leaves it nil.
func (c *Corpus) Prefetch(prefetch func([]string)) { c.prefetch = prefetch }

// Analyze turns a corpus into judged edges, most severe first. The parse and
// the judgment are separate passes so every target's facts can be read once,
// and so the two sources judge the same structure the same way.
func Analyze(corpus *Corpus) []Edge {
	if corpus == nil || corpus.facts == nil {
		return nil
	}
	raw := analyzeSystemd(corpus)
	for _, file := range corpus.files {
		if corpus.stopped() {
			break
		}
		switch file.Surface {
		case SurfaceSystemd:
			if file.Dialect == GeneratorsDialect {
				raw = append(raw, generatorEdges(file)...)
			}
		case SurfaceProfile:
			base := rawEdge{
				surface: SurfaceProfile,
				phase:   Login,
				subject: accountFor(file.Path),
				trigger: file.Path,
			}
			switch file.Dialect {
			case ShellDialect:
				raw = append(raw, shellEdges(file.Body, base)...)
			case EnvDialect:
				raw = append(raw, environmentEdges(file.Body, base)...)
			}
		case SurfaceInit:
			reach := BootStaged
			if _, enabled := corpus.enabled[filepath.Base(file.Path)]; enabled {
				reach = BootEnabled
			}
			raw = append(raw, shellEdges(file.Body, rawEdge{
				surface: SurfaceInit, phase: reach, subject: Subject{Class: AccountRoot}, trigger: file.Path,
			})...)
		case SurfaceCron:
			if file.Dialect == ShellDialect {
				raw = append(raw, shellEdges(file.Body, rawEdge{
					surface: SurfaceCron, phase: Scheduled, subject: cronShellSubject(file.Path), trigger: file.Path,
				})...)
			} else {
				raw = append(raw, cronEdges(file)...)
			}
		case SurfaceLoader:
			raw = append(raw, loaderEdges(file)...)
		case SurfaceUdev:
			raw = append(raw, udevEdges(file)...)
		case SurfaceSSH:
			switch file.Dialect {
			case AuthorizedKeysDialect:
				raw = append(raw, authorizedKeysEdges(file)...)
			case SSHConfigDialect:
				raw = append(raw, sshConfigEdges(file)...)
			default:
				raw = append(raw, shellEdges(file.Body, rawEdge{
					surface: SurfaceSSH, phase: Login, subject: accountFor(file.Path), trigger: file.Path,
				})...)
			}
		case SurfacePAM:
			if file.Dialect == ShellDialect {
				// The login banner's run-parts script: it runs itself, and it
				// may source or run objects of its own.
				raw = append(raw, motdEdges(file)...)
			} else {
				raw = append(raw, pamEdges(file, corpus)...)
			}
		case SurfaceSupervisor:
			if file.Dialect == XinetdDialect {
				raw = append(raw, xinetdEdges(file)...)
			} else {
				raw = append(raw, supervisorEdges(file)...)
			}
		case SurfaceSystem:
			raw = append(raw, systemEdges(file, corpus)...)
		case SurfaceXdg:
			raw = append(raw, desktopEdges(file)...)
		case SurfaceApt:
			raw = append(raw, aptEdges(file)...)
		case SurfaceModule:
			raw = append(raw, modprobeEdges(file)...)
		}
	}

	// The trigger lines are the quotes a finding can carry; one split per
	// path keeps the lookup cheap when a file states many edges.
	sourceLines := make(map[string][]string, len(corpus.files))
	for _, file := range corpus.files {
		if _, ok := sourceLines[file.Path]; ok {
			continue
		}
		sourceLines[file.Path] = strings.Split(file.Body, "\n")
	}

	targets := make([]string, 0, len(raw)*2)
	for _, edge := range raw {
		// Prefetch both ends: every unit file, drop-in and profile script is a
		// trigger, and asking for its package ownership one path at a time is
		// what makes a wide collection slow on a host with many packages.
		if edge.trigger != "" {
			targets = append(targets, edge.trigger)
		}
		if !edge.dynamic && edge.target != "" {
			targets = append(targets, edge.target)
		}
	}
	if corpus.prefetch != nil {
		corpus.prefetch(targets)
	}
	cache := make(map[string]trust.Facts, len(targets)+len(raw))
	facts := func(path string) trust.Facts {
		if facts, ok := cache[path]; ok {
			return facts
		}
		read := corpus.facts(path)
		cache[path] = read
		return read
	}

	edges := make([]Edge, 0, len(raw))
	seenSelf := map[string]bool{}
	for _, edge := range raw {
		if corpus.stopped() {
			break
		}
		judged := Edge{
			Surface:   edge.surface,
			Phase:     edge.phase,
			Subject:   edge.subject,
			Trigger:   edge.trigger,
			Line:      edge.line,
			Mechanism: edge.mechanism,
			Target:    edge.target,
			Kind:      edge.kind,
			Dynamic:   edge.dynamic,
			Context:   edge.context,
			Note:      edge.note,
		}
		if edge.line > 0 {
			if lines, ok := sourceLines[edge.trigger]; ok && edge.line <= len(lines) {
				judged.Source = strings.TrimSpace(lines[edge.line-1])
			}
		}
		if !edge.dynamic {
			target := facts(edge.target)
			if edge.kind == Env && !envTarget(target) {
				// A variable holding an install prefix (JAVA_HOME), a PATH
				// fragment, or a runtime file (a pid or lock file in /run)
				// names something a later session will not read as a script.
				// The file-valued assignment is the edge.
				continue
			}
			judged.TriggerFacts = facts(edge.trigger)
			judged.TargetFacts = target
			// A self-edge names one file twice. On a usrmerge host /lib and
			// /usr/lib are the same tree, so the resolved path — one lookup
			// per run — decides whether this is another object.
			if edge.trigger == edge.target {
				if seenSelf[target.Real] {
					continue
				}
				seenSelf[target.Real] = true
			}
		}
		edges = append(edges, judged)
	}
	sort.SliceStable(edges, func(i, j int) bool {
		left, right := edges[i], edges[j]
		if left.Surface != right.Surface {
			return left.Surface < right.Surface
		}
		if left.Trigger != right.Trigger {
			return left.Trigger < right.Trigger
		}
		if left.Target != right.Target {
			return left.Target < right.Target
		}
		return left.Line < right.Line
	})
	return edges
}

// mountNote is a mount row's Type= and Options= for the What edge's note.
func mountNote(state *unitState) string {
	var parts []string
	if kind := state.mount["Type"]; kind != "" {
		parts = append(parts, "type="+kind)
	}
	if options := state.mount["Options"]; options != "" {
		parts = append(parts, "options="+options)
	}
	return strings.Join(parts, " ")
}

// analyzeSystemd folds each unit's files and drop-ins, then states the edges
// its service keys carry.
func analyzeSystemd(corpus *Corpus) []rawEdge {
	units := make(map[string][]File)
	var order []string
	for _, file := range corpus.files {
		if file.Surface != SurfaceSystemd || file.Unit == "" {
			continue
		}
		if _, seen := units[file.Unit]; !seen {
			order = append(order, file.Unit)
		}
		units[file.Unit] = append(units[file.Unit], file)
	}

	var edges []rawEdge
	for _, name := range order {
		state := applyFiles(units[name])
		reach := BootStaged
		if _, enabled := corpus.enabled[name]; enabled {
			reach = BootEnabled
		}
		subject := unitAccount(units[name])
		if state.userSet {
			subject = state.subject
		}
		if state.dynamic {
			subject = Subject{Class: AccountDynamic}
		}
		for _, key := range execOrder {
			for _, ref := range state.exec[key] {
				target := execTarget(ref.value)
				if target.target == "" && !target.dynamic {
					continue
				}
				kind := target.kind
				if kind == "" {
					kind = Exec
				}
				edges = append(edges, rawEdge{
					surface:        SurfaceSystemd,
					phase:          reach,
					subject:        subject,
					trigger:        ref.file,
					line:           ref.line,
					mechanism:      Mechanism(key),
					target:         target.target,
					kind:           kind,
					viaInterpreter: target.viaInterpreter,
					dynamic:        target.dynamic,
				})
			}
		}
		for _, ref := range state.what {
			// A mount or swap unit's source: an absolute device path is an
			// edge, a network location stays dynamic — the boot fills the
			// mount point from whatever What names.
			words := splitWords(ref.value)
			if len(words) == 0 {
				continue
			}
			source := words[0]
			note := source
			if extra := mountNote(state); extra != "" {
				note += " " + extra
			}
			edges = append(edges, rawEdge{
				surface:   SurfaceSystemd,
				phase:     reach,
				subject:   subject,
				trigger:   ref.file,
				line:      ref.line,
				mechanism: "What",
				target:    source,
				kind:      Config,
				dynamic:   !filepath.IsAbs(source),
				note:      note,
			})
		}
		for _, ref := range state.envFiles {
			words := splitWords(ref.value)
			if len(words) == 0 {
				continue
			}
			path := strings.TrimPrefix(words[0], "-")
			edges = append(edges, rawEdge{
				surface:   SurfaceSystemd,
				phase:     reach,
				subject:   subject,
				trigger:   ref.file,
				line:      ref.line,
				mechanism: "EnvironmentFile",
				target:    path,
				kind:      Config,
				dynamic:   !filepath.IsAbs(path),
			})
		}
		for _, ref := range state.context {
			edges = append(edges, rawEdge{
				surface:   SurfaceSystemd,
				phase:     reach,
				subject:   subject,
				trigger:   ref.file,
				line:      ref.line,
				mechanism: Mechanism(ref.key),
				target:    ref.path,
				kind:      Config,
				context:   true,
			})
		}
		for _, ref := range state.env {
			name, paths := environmentPreloads(ref.value)
			for _, path := range paths {
				edges = append(edges, rawEdge{
					surface:   SurfaceSystemd,
					phase:     reach,
					subject:   subject,
					trigger:   ref.file,
					line:      ref.line,
					mechanism: Mechanism("Environment=" + name),
					target:    path,
					kind:      Preload,
				})
			}
		}
	}
	return edges
}

// envTarget reports whether an exported path is a file a later session could
// read as a unit of code: a regular executable, a hidden file, or a file in an
// administrator's tree. A directory, a list, or a runtime pid/lock file is not.
func envTarget(facts trust.Facts) bool {
	if facts.Kind != trust.File {
		return false
	}
	return facts.Executable || facts.Hidden || facts.AdminLayer
}

// accountFor is who reads a per-user startup file: the root home runs as root,
// another home as that user, and a system-wide file as whichever account logs
// in.
func accountFor(path string) Subject {
	if strings.HasPrefix(path, "/root/") {
		return Subject{Class: AccountRoot}
	}
	if user, ok := homeAccount(path); ok {
		return Account(user)
	}
	return Subject{Class: AccountLogin}
}

// homeAccount reads the account out of /home/<user>/...
func homeAccount(path string) (string, bool) {
	rest, ok := strings.CutPrefix(path, "/home/")
	if !ok {
		return "", false
	}
	user, _, found := strings.Cut(rest, "/")
	if !found || user == "" {
		return "", false
	}
	return user, true
}

// unitAccount is a unit's default account when the unit does not set User=:
// the system manager runs as root, the user manager as the account whose
// config tree holds the unit.
func unitAccount(files []File) Subject {
	for _, file := range files {
		if user, ok := homeAccount(file.Path); ok {
			return Account(user)
		}
		if strings.HasPrefix(file.Path, "/root/.config/systemd/user/") {
			return Subject{Class: AccountRoot}
		}
		if strings.HasPrefix(file.Path, "/etc/systemd/user/") {
			return Subject{Class: AccountLogin}
		}
	}
	return Subject{Class: AccountRoot}
}
