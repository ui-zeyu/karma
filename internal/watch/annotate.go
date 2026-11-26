package watch

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"karma/internal/audit"
	"karma/internal/prov"
	"karma/internal/startup"
	"karma/internal/trust"
)

// maxFactsCache bounds one annotator's path cache. A burst past the bound
// drops the cache whole: re-stating a path costs one stat, an unbounded cache
// costs memory and answers gone stale.
const maxFactsCache = 4096

// factsTTL bounds how long one path's cached facts describe the disk. A live
// watcher runs for hours; a replaced binary or a permission change has to be
// seen without waiting for 4096 unrelated paths.
const factsTTL = 5 * time.Second

// Annotator adds the structural facts a line needs without asking a name what
// it means: is the executable package-owned, is it in an administrator layer,
// is the working directory one, is an interpreter carrying a script. The facts
// are cached by path; the package catalog answers from its own index, so an
// event burst costs no package-manager call.
type cachedFacts struct {
	facts trust.Facts
	at    time.Time
}

type Annotator struct {
	catalog  *prov.Catalog
	facts    map[string]cachedFacts
	observer *audit.Observer
}

// NewAnnotator uses the host's package database.
func NewAnnotator() *Annotator {
	return NewAnnotatorWith(prov.Open(context.Background()))
}

// NewAnnotatorWith builds an annotator over a given catalog; nil answers
// unknown and is what the tests use.
func NewAnnotatorWith(catalog *prov.Catalog) *Annotator {
	return &Annotator{catalog: catalog, facts: map[string]cachedFacts{}, observer: audit.NewObserverWith(catalog)}
}

// share returns an annotator over the same catalog and observer with its own
// path cache. The pipeline's workers each annotate with their own share, so
// the caches never share a map.
func (a *Annotator) share() *Annotator {
	return &Annotator{catalog: a.catalog, facts: map[string]cachedFacts{}, observer: a.observer}
}

// Annotate attaches the flags and, where the event carries a running image,
// the verdict.
func (a *Annotator) Annotate(ev *Event) {
	switch {
	case ev.Proc != nil:
		a.annotateProc(ev, ev.Proc)
	case ev.Sock != nil:
		a.annotateSock(ev, ev.Sock)
	}
}

func (a *Annotator) annotateProc(ev *Event, proc *Proc) {
	flags := newFlagSet(ev.Flags)
	exe := proc.Exe
	if strings.HasSuffix(exe, " (deleted)") {
		exe = strings.TrimSuffix(exe, " (deleted)")
		proc.Exe = exe
		flags.add(FlagDeleted)
	}
	script, _ := a.scriptFacts(ev.Proc)
	if script != "" {
		proc.Script = script
	}
	if exe != "" {
		facts := a.classify(exe)
		a.addFacts(flags, facts)
		if facts.Executable && facts.PackageKnown && facts.Package == "" {
			flags.add(FlagUnownedExec)
		}
	}
	if proc.Cwd != "" {
		if facts := a.classify(proc.Cwd); facts.AdminLayer || facts.PathAdmin {
			flags.add(FlagAdminCwd)
		}
	}
	if script != "" {
		scriptFacts := a.classify(script)
		if scriptFacts.AdminLayer || scriptFacts.PathAdmin {
			flags.add(FlagAdminScript)
		}
		if scriptFacts.PackageKnown && scriptFacts.Package == "" {
			flags.add(FlagUnownedScript)
		}
	}
	// An exec whose image the source could not read (the process was gone
	// before /proc answered) carries no judgment: an empty image would read
	// as unknown, which is a finding-shaped answer to a read that never
	// happened. The no-image flag keeps the event itself greppable, and the
	// writer counts them so a burst — a dropper's signature — is named.
	if proc.Kind == KindExec && proc.Exe == "" {
		flags.add(FlagNoImage)
	}
	ev.Flags = flags.sorted()
	if proc.Kind == KindExec && proc.Exe != "" {
		image, scriptFacts := a.classify(exe), a.classify(script)
		ev.Verdict = verdict(a.observer.Observe(image, scriptFacts, proc.UID))
	}
}

func (a *Annotator) annotateSock(ev *Event, sock *Sock) {
	flags := newFlagSet(ev.Flags)
	if sock.Exe != "" {
		facts := a.classify(sock.Exe)
		a.addFacts(flags, facts)
		if facts.Executable && facts.PackageKnown && facts.Package == "" {
			flags.add(FlagUnownedExec)
		}
		if sock.Cwd != "" {
			if facts := a.classify(sock.Cwd); facts.AdminLayer || facts.PathAdmin {
				flags.add(FlagAdminCwd)
			}
		}
		script, ok := a.sockScript(sock)
		if ok {
			scriptFacts := a.classify(script)
			if scriptFacts.AdminLayer || scriptFacts.PathAdmin {
				flags.add(FlagAdminScript)
			}
			if scriptFacts.PackageKnown && scriptFacts.Package == "" {
				flags.add(FlagUnownedScript)
			}
		}
		ev.Verdict = verdict(a.observer.Observe(a.classify(sock.Exe), factsOf(a, script), sock.UID))
	}
	ev.Flags = flags.sorted()
}

// verdict builds the judgment an Observe call answered.
func verdict(origin audit.Origin, reach audit.Reach, severity audit.Severity) *Verdict {
	return &Verdict{Origin: origin, Reach: reach, Severity: severity}
}

// factsOf answers the facts of a script path, or zero facts for none.
func factsOf(a *Annotator, script string) trust.Facts {
	if script == "" {
		return trust.Facts{}
	}
	return a.classify(script)
}

func (a *Annotator) addFacts(flags *flagSet, facts trust.Facts) {
	if facts.PackageKnown && facts.Package == "" {
		flags.add(FlagUnowned)
	}
	if facts.AdminLayer || facts.PathAdmin {
		flags.add(FlagAdmin)
	}
	if facts.Hidden || facts.PathHidden {
		flags.add(FlagHidden)
	}
	if facts.Writable {
		flags.add(FlagWritable)
	}
}

// scriptFacts reads the script an interpreter carries. A relative argument is
// joined to the event's cwd; a relative name that does not resolve to a file is
// an option value or a module, not a script.
func (a *Annotator) scriptFacts(proc *Proc) (string, bool) {
	if !startup.IsInterpreter(proc.Exe) {
		return "", false
	}
	script := startup.ScriptArgv(proc.Args)
	if script == "" && len(proc.Args) == 0 {
		script = startup.ScriptArg(proc.Cmdline)
	}
	if script == "" {
		return "", false
	}
	path := script
	if !filepath.IsAbs(path) {
		if proc.Cwd == "" {
			return "", false
		}
		path = filepath.Join(proc.Cwd, path)
	}
	facts := a.classify(path)
	if !filepath.IsAbs(script) && facts.Kind != trust.File {
		return "", false
	}
	return path, true
}

// sockScript reads the script a socket owner's interpreter carries, joined to
// the owner's working directory.
func (a *Annotator) sockScript(sock *Sock) (string, bool) {
	if !startup.IsInterpreter(sock.Exe) || sock.Cmdline == "" {
		return "", false
	}
	fake := &Proc{Exe: sock.Exe, Cmdline: sock.Cmdline, Args: sock.Args, Cwd: sock.Cwd}
	return a.scriptFacts(fake)
}

func (a *Annotator) classify(path string) trust.Facts {
	if path == "" {
		return trust.Facts{}
	}
	if cached, ok := a.facts[path]; ok && time.Since(cached.at) < factsTTL {
		return cached.facts
	}
	if len(a.facts) >= maxFactsCache {
		a.facts = map[string]cachedFacts{}
	}
	facts := trust.Classify(path, a.catalog)
	a.facts[path] = cachedFacts{facts: facts, at: time.Now()}
	return facts
}

// flagSet collects an event's flags and prints them in the table's order.
type flagSet struct {
	seen map[Flag]bool
}

func newFlagSet(existing []Flag) *flagSet {
	set := &flagSet{seen: map[Flag]bool{}}
	for _, flag := range existing {
		set.seen[flag] = true
	}
	return set
}

func (f *flagSet) add(flag Flag) { f.seen[flag] = true }

func (f *flagSet) sorted() []Flag {
	if len(f.seen) == 0 {
		return nil
	}
	out := make([]Flag, 0, len(f.seen))
	for _, flag := range flagOrder {
		if f.seen[flag] {
			out = append(out, flag)
			delete(f.seen, flag)
		}
	}
	return out
}
