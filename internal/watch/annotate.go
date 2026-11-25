package watch

import (
	"path/filepath"
	"sort"
	"strings"

	"karma/internal/audit"
	"karma/internal/startup"
	"karma/internal/trust"
)

// Annotator adds the structural facts a line needs without asking a name what
// it means: is the executable package-owned, is it in an administrator layer,
// is the working directory one, is an interpreter carrying a script. The facts
// are cached by path; the package resolver has its own cache behind them.
type Annotator struct {
	resolver trust.PackageResolver
	facts    map[string]trust.Facts
	observer *audit.Observer
}

// NewAnnotator uses the host's package manager.
func NewAnnotator() *Annotator {
	return NewAnnotatorWith(trust.NewResolver())
}

// NewAnnotatorWith builds an annotator over a given resolver; nil is a
// resolver that answers unknown and is what the tests use.
func NewAnnotatorWith(resolver trust.PackageResolver) *Annotator {
	return &Annotator{resolver: resolver, facts: map[string]trust.Facts{}, observer: audit.NewObserver()}
}

// Annotate writes the event's flags in place.
func (a *Annotator) Annotate(ev *Event) {
	flags := newFlagSet(ev.Flags)
	deleted := false
	exe := ev.Exe
	if strings.HasSuffix(exe, " (deleted)") {
		exe = strings.TrimSuffix(exe, " (deleted)")
		deleted = true
	}
	if deleted {
		flags.add("deleted")
	}
	if exe != "" {
		facts := a.classify(exe)
		a.addFacts(flags, facts)
		if facts.Executable && facts.PackageKnown && facts.Package == "" {
			flags.add("unowned-exec")
		}
	}
	if ev.Cwd != "" {
		if facts := a.classify(ev.Cwd); facts.AdminLayer || facts.PathAdmin {
			flags.add("admin-cwd")
		}
	}
	if script, ok := a.scriptFacts(ev, exe); ok {
		if script.AdminLayer {
			flags.add("admin-script")
		}
		if script.PackageKnown && script.Package == "" {
			flags.add("unowned-script")
		}
	}
	if exe != "" && (ev.Kind == KindExec || ev.Kind == KindSocket) {
		origin, reach, severity := a.judge(ev, exe)
		ev.Origin = origin.String()
		ev.Reach = reach.String()
		ev.Severity = severity.String()
	}
	ev.Flags = flags.sorted()
}

// judge reads the image an event runs through the audit's origin model: the
// image and the script an interpreter carries both answer against the artifact
// boundary, and the weaker origin wins.
func (a *Annotator) judge(ev *Event, exe string) (audit.Origin, audit.Reach, audit.Severity) {
	script, ok := a.scriptFacts(ev, exe)
	if !ok {
		script = trust.Facts{}
	}
	return a.observer.Observe(a.classify(exe), script, ev.UID)
}

// scriptFacts reads the script an interpreter carries. A relative argument is
// joined to the event's cwd; a relative name that does not resolve to a file is
// an option value or a module, not a script.
func (a *Annotator) scriptFacts(ev *Event, exe string) (trust.Facts, bool) {
	if !startup.IsInterpreter(exe) {
		return trust.Facts{}, false
	}
	script := startup.ScriptArg(ev.Cmdline)
	if script == "" {
		return trust.Facts{}, false
	}
	path := script
	if !filepath.IsAbs(path) {
		if ev.Cwd == "" {
			return trust.Facts{}, false
		}
		path = filepath.Join(ev.Cwd, path)
	}
	facts := a.classify(path)
	if !filepath.IsAbs(script) && facts.Kind != trust.File {
		return trust.Facts{}, false
	}
	return facts, true
}

func (a *Annotator) classify(path string) trust.Facts {
	if facts, ok := a.facts[path]; ok {
		return facts
	}
	facts := trust.Classify(path, a.resolver)
	a.facts[path] = facts
	return facts
}

func (a *Annotator) addFacts(flags *flagSet, facts trust.Facts) {
	if facts.PackageKnown && facts.Package == "" {
		flags.add("unowned")
	}
	if facts.AdminLayer || facts.PathAdmin {
		flags.add("admin")
	}
	if facts.Hidden || facts.PathHidden {
		flags.add("hidden")
	}
	if facts.Writable {
		flags.add("writable")
	}
}

// flagOrder is the order flags print in, so a line reads the same whatever
// sequence the events arrived in.
var flagOrder = []string{
	"deleted", "unowned", "unowned-exec", "admin", "hidden", "writable",
	"admin-cwd", "unowned-script", "admin-script",
}

type flagSet struct {
	seen map[string]bool
}

func newFlagSet(existing []string) *flagSet {
	set := &flagSet{seen: map[string]bool{}}
	for _, flag := range existing {
		set.seen[flag] = true
	}
	return set
}

func (f *flagSet) add(flag string) { f.seen[flag] = true }

func (f *flagSet) sorted() []string {
	if len(f.seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(f.seen))
	for _, flag := range flagOrder {
		if f.seen[flag] {
			out = append(out, flag)
			delete(f.seen, flag)
		}
	}
	// A flag outside the table (a source's own word) follows the known ones in
	// byte order; the table is the vocabulary, so this is rare.
	rest := make([]string, 0, len(f.seen))
	for flag := range f.seen {
		rest = append(rest, flag)
	}
	sort.Strings(rest)
	return append(out, rest...)
}
