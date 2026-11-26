package audit

import (
	"strconv"
	"strings"

	"karma/internal/startup"
	"karma/internal/trust"
)

// Domain is one area of the host a run can collect. The CLI selection becomes
// a Plan, and the collectors read only the domains the plan names: a service
// query does not pay for the authority walk, a file query does not read
// /proc.
type Domain uint16

const (
	// DomainBase is the shared context every run reads: the artifact boundary,
	// the package timeline, the content ledger's timestamps and the mount
	// table. It has no collector of its own.
	DomainBase Domain = 1 << iota
	DomainServices
	DomainProcesses
	DomainNetwork
	DomainPersistence
	DomainAuthority
	DomainFiles
	// DomainKernel reads the running kernel's module registries, taint mask
	// and pid space, and the dynamic loader's search path. These are runtime
	// state and loader configuration, not activation files; the kernel domain
	// is where a rootkit leaves evidence no file path carries.
	DomainKernel
	// DomainPackages sweeps every package file list against each package's
	// transaction time. It is the global provenance graph; the content
	// ledger remains the precise, scoped answer.
	DomainPackages
	// DomainWeb sweeps the web roots for scripts whose origin is outside the
	// artifact.
	DomainWeb
	// DomainIdentity parses accounts, groups, sudo grants, shadow state and
	// SSH keys into the identity graph.
	DomainIdentity
	// DomainTrail reads the interactive trails a person leaves: shell
	// history, viminfo, known_hosts and authentication logs. They are
	// evidence sources, not findings of their own; the judge cites the lines
	// that name an object already under judgment.
	DomainTrail
)

// AllDomains is every bounded domain. It is the bare `karma` run.
const AllDomains = DomainBase | DomainServices | DomainProcesses | DomainNetwork |
	DomainPersistence | DomainAuthority | DomainFiles | DomainKernel | DomainPackages | DomainWeb | DomainIdentity | DomainTrail

// GraphSeed is one object-graph selector, parsed once for the plan, the
// collection and the walk.
type GraphSeed struct {
	Kind  string // unit, pid, path, package
	Value string
}

// Plan is what one run reads: the Filter's scope, plus the inventory roots an
// object scan may add and the object graph's seed. The embedded Filter is the
// one range state the collectors, the judges and the views read.
type Plan struct {
	Filter
	InventoryRoots []string
	// Seed is the object an object graph grew from, when the run named one.
	// The collector scopes the unit inventory, the process scan and the
	// socket owner scan to it; every other run leaves it zero.
	Seed GraphSeed
}

// collects reports whether the plan reads a domain, either because the domain
// is judged or because a selected module needs its rows as context.
func (p Plan) collects(domain Domain) bool {
	if p.Domains == 0 || p.Has(domain) {
		return true
	}
	if domain == DomainProcesses && p.Has(DomainTrail) &&
		(len(p.PIDs) > 0 || len(p.Units) > 0 || len(p.ExcludePIDs) > 0 || len(p.ExcludeUnits) > 0) {
		// A trail row's owner is a process; a pid or unit scope needs the
		// process table even when no process finding is judged.
		return true
	}
	return p.collectedDomains()&domain != 0
}

// collectedDomains closes the selected domains over Module.Needs. A domain
// collected as context still contributes its rows but never its findings.
func (p Plan) collectedDomains() Domain {
	if p.Domains == 0 {
		return AllDomains
	}
	domains := p.Domains
	for changed := true; changed; {
		changed = false
		for _, module := range modules {
			if domains&module.Bit == 0 || module.Needs == 0 {
				continue
			}
			if next := domains | module.Needs; next != domains {
				domains = next
				changed = true
			}
		}
	}
	return domains
}

// touchesPath reports whether a walk rooted at path can answer the scope: a
// positive path is equal, below or above the root, and an excluded root is
// skipped. It is the pushdown every tree walk uses, so a path audit does not
// pay for unrelated trees.
func (f Filter) touchesPath(path string) bool {
	if path == "" || f.pathExcluded(path) {
		return false
	}
	if len(f.Paths) == 0 {
		return true
	}
	if path == "/" {
		return true
	}
	for _, root := range f.Paths {
		if path == root || strings.HasPrefix(path, root+"/") || strings.HasPrefix(root, path+"/") {
			return true
		}
	}
	return false
}

// globalScope reports whether the run asks about the host as a whole rather
// than one object. Global checks (clock, hidden pids, hidden modules) run only
// here.
func (f Filter) globalScope() bool {
	return len(f.Paths) == 0 && len(f.PIDs) == 0 && len(f.Units) == 0
}

// seedUnit is the unit an object graph selected, or "" when the seed names
// another kind of object.
func (p Plan) seedUnit() string {
	if p.Seed.Kind == "unit" {
		return p.Seed.Value
	}
	return ""
}

// PathDomains answers the domains a path scope can explain. A file path is
// judged against the artifact boundary, the activation surfaces that name it,
// the authority and package ownership that give it meaning, and the files
// inventory; process, network, service and kernel state are added only when
// the path is in their own trees.
func PathDomains(paths []string) Domain {
	domains := DomainBase | DomainPersistence | DomainFiles | DomainAuthority | DomainPackages
	for _, path := range paths {
		if path == "/" {
			return AllDomains
		}
		if underAnyPathPrefix(path, []string{
			"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers", "/etc/sudoers.d",
			"/etc/ssh", "/home", "/root",
		}) {
			domains |= DomainIdentity
		}
		if underAnyPathPrefix(path, webRoots) {
			domains |= DomainWeb
		}
		if underAnyPathPrefix(path, []string{
			"/lib/modules", "/usr/lib/modules", "/etc/modules", "/etc/modules-load.d",
			"/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/ld.so.preload", "/sys/module",
		}) {
			domains |= DomainKernel
		}
		if underAnyPathPrefix(path, []string{"/etc/systemd", "/run/systemd", "/usr/lib/systemd", "/lib/systemd"}) {
			domains |= DomainServices
		}
		if underAnyPathPrefix(path, []string{"/var/log/auth.log", "/var/log/secure", "/root", "/home"}) {
			domains |= DomainTrail
		}
	}
	return domains
}

func underAnyPathPrefix(path string, roots []string) bool {
	for _, root := range roots {
		if trust.Under(path, root) || trust.Under(root, path) {
			return true
		}
	}
	return false
}

// FullPlan reads every bounded domain. The static inventory walks the program
// directories unless InventoryRoots names other trees.
func FullPlan() Plan {
	return Plan{Filter: Filter{Domains: AllDomains}}
}

// ObjectGraphPlan reads the context one object's graph needs. A unit explains
// itself through systemd, its processes and their sockets; a pid through the
// process table and its sockets; a path or a package may be named by any
// activation surface, so the walk reads them all. The authority walk and the
// static inventory explain no single object, so an object graph stays cheap.
func ObjectGraphPlan(seed GraphSeed) Plan {
	plan := Plan{
		Filter: Filter{Domains: DomainBase | DomainServices | DomainProcesses | DomainNetwork | DomainPersistence},
		Seed:   seed,
	}
	switch seed.Kind {
	case "unit":
		plan.Domains = DomainBase | DomainServices | DomainProcesses | DomainNetwork | DomainPersistence
		plan.Surfaces = surfacePtr(startup.SurfaceScope(startup.SurfaceSystemd))
	case "pid":
		plan.Domains = DomainBase | DomainProcesses | DomainNetwork
		plan.Surfaces = surfacePtr(0)
	case "path":
		// The graph already reads the activation surfaces and the process
		// table; add the domain a path in that tree can explain without
		// paying for the authority or package walks.
		plan.Domains |= PathDomains([]string{seed.Value}) &
			(DomainKernel | DomainWeb | DomainIdentity | DomainTrail)
	}
	return plan
}

// Has reports whether the plan selected a domain.
func (p Plan) Has(domain Domain) bool { return p.Domains&domain != 0 }

// surfacePtr names an explicit surface set; zero selects none.
func surfacePtr(scope startup.Scope) *startup.Scope { return &scope }

// StartupScope is the registry union of the selected domains' startup needs.
// The CLI uses it when no scope word names a startup surface.
func StartupScope(domains Domain) startup.Scope {
	if domains == 0 {
		return startup.AllScope()
	}
	var scope startup.Scope
	for _, module := range modules {
		if domains&module.Bit != 0 && module.Startup != nil {
			scope |= module.Startup()
		}
	}
	return scope
}

// startupScope answers which startup collectors the plan turns on. An
// explicit surface set wins; otherwise the registry union of the selected
// domains decides.
func (p Plan) startupScope() startup.Scope {
	if p.Surfaces != nil {
		return *p.Surfaces
	}
	return StartupScope(p.collectedDomains())
}

// seedPids names the processes an object graph's socket scan needs: the selected
// pid, the pids in the selected unit's cgroup, the processes running a selected
// path, or the processes whose image belongs to a selected package.
func seedPids(seed GraphSeed, processes []Process) map[int]bool {
	pids := map[int]bool{}
	addUnit := func(unit string) {
		for _, process := range processes {
			if process.Unit == unit || templateUnit(process.Unit) == unit {
				pids[process.PID] = true
			}
		}
	}
	addPath := func(path string) {
		for _, process := range processes {
			if process.Exe == path || process.Script == path ||
				strings.HasPrefix(process.Exe, path+"/") || strings.HasPrefix(process.Script, path+"/") {
				pids[process.PID] = true
			}
		}
	}
	addPackage := func(pkg string) {
		for _, process := range processes {
			if process.ExeFacts.Package == pkg || process.ScriptFacts.Package == pkg {
				pids[process.PID] = true
			}
		}
	}
	switch seed.Kind {
	case "pid":
		if pid, err := strconv.Atoi(seed.Value); err == nil {
			pids[pid] = true
		}
	case "unit":
		addUnit(seed.Value)
	case "path":
		addPath(seed.Value)
	case "package":
		addPackage(seed.Value)
	}
	return pids
}
