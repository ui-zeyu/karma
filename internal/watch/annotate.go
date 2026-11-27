package watch

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"karma/internal/audit"
	"karma/internal/prov"
	"karma/internal/startup"
	"karma/internal/trust"
)

// maxFactsCache bounds the annotators' shared path cache: the workers evict
// the earliest inserted quarter per shard instead of dropping the table whole,
// so a burst past the bound costs a few re-stats, not a cold cache.
const maxFactsCache = 4096

// factsShards is the width of the shared cache. Each shard locks its own map,
// so the pipeline's four workers answer without contending on one lock.
const factsShards = 16

// factsShardCap is one shard's bound, so the whole cache stays inside
// maxFactsCache entries.
const factsShardCap = maxFactsCache / factsShards

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

// factsShard is one lock, one map and the keys in insertion order for the
// eviction. The TTL lives on each entry: get answers stale facts only as a
// miss, and the next classify restates them.
type factsShard struct {
	mu     sync.Mutex
	byPath map[string]cachedFacts
	order  []string
}

// factsCache is the annotators' shared path cache. Every annotator a run
// builds — including each worker's share — points at one cache, so a path
// stated once is answered from memory by every worker.
type factsCache struct {
	shards [factsShards]factsShard
}

func newFactsCache() *factsCache {
	cache := &factsCache{}
	for index := range cache.shards {
		cache.shards[index].byPath = map[string]cachedFacts{}
	}
	return cache
}

// shardOf picks the shard by the path's FNV-1a, so a path always lands in the
// same shard.
func (c *factsCache) shardOf(path string) *factsShard {
	hash := uint32(2166136261)
	for index := 0; index < len(path); index++ {
		hash ^= uint32(path[index])
		hash *= 16777619
	}
	return &c.shards[hash%factsShards]
}

// get answers the path's cached facts while they are fresh.
func (s *factsShard) get(path string) (trust.Facts, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cached, ok := s.byPath[path]
	if !ok || time.Since(cached.at) >= factsTTL {
		return trust.Facts{}, false
	}
	return cached.facts, true
}

// put states one path's facts, evicting the earliest inserted quarter when the
// shard is full.
func (s *factsShard) put(path string, facts trust.Facts) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byPath[path]; !ok && len(s.order) >= factsShardCap {
		s.evictLocked(factsShardCap / 4)
	}
	if _, ok := s.byPath[path]; !ok {
		s.order = append(s.order, path)
	}
	s.byPath[path] = cachedFacts{facts: facts, at: time.Now()}
}

// evictLocked drops the n earliest inserted keys and compacts the order in
// place, so the backing array stays bounded.
func (s *factsShard) evictLocked(n int) {
	if n > len(s.order) {
		n = len(s.order)
	}
	for _, path := range s.order[:n] {
		delete(s.byPath, path)
	}
	s.order = append(s.order[:0], s.order[n:]...)
}

type Annotator struct {
	catalog  *prov.Catalog
	facts    *factsCache
	observer *audit.Observer
}

// NewAnnotator uses the host's package database. A nil context falls back to
// background, since the annotator is also built outside a request's scope.
func NewAnnotator(ctx context.Context) *Annotator {
	if ctx == nil {
		ctx = context.Background()
	}
	return NewAnnotatorWith(prov.Open(ctx))
}

// NewAnnotatorWith builds an annotator over a given catalog; nil answers
// unknown and is what the tests use.
func NewAnnotatorWith(catalog *prov.Catalog) *Annotator {
	return &Annotator{catalog: catalog, facts: newFactsCache(), observer: audit.NewObserverWith(catalog)}
}

// share returns an annotator over the same catalog, observer and path cache.
// The pipeline's workers each annotate through their own share; the cache is
// sharded and locked, so the workers share it safely.
func (a *Annotator) share() *Annotator {
	return &Annotator{catalog: a.catalog, facts: a.facts, observer: a.observer}
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
			// The flag is the conclusion; the path is the evidence the line
			// and the JSON carry.
			sock.Script = script
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
	shard := a.facts.shardOf(path)
	if facts, ok := shard.get(path); ok {
		return facts
	}
	facts := trust.Classify(path, a.catalog)
	shard.put(path, facts)
	return facts
}

// flagSet collects an event's flags and prints them in the table's order. The
// set is a handful of flags per event, so a small slice beats a map.
type flagSet struct {
	flags []Flag
}

func newFlagSet(existing []Flag) *flagSet {
	return &flagSet{flags: append([]Flag(nil), existing...)}
}

func (f *flagSet) has(flag Flag) bool {
	for _, set := range f.flags {
		if set == flag {
			return true
		}
	}
	return false
}

func (f *flagSet) add(flag Flag) {
	if !f.has(flag) {
		f.flags = append(f.flags, flag)
	}
}

func (f *flagSet) sorted() []Flag {
	if len(f.flags) == 0 {
		return nil
	}
	out := make([]Flag, 0, len(f.flags))
	for _, flag := range flagOrder {
		if f.has(flag) {
			out = append(out, flag)
		}
	}
	return out
}
