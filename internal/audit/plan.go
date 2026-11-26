package audit

import (
	"strconv"
	"strings"

	"karma/internal/startup"
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
)

// AllDomains is every bounded domain. It is the bare `karma` run.
const AllDomains = DomainBase | DomainServices | DomainProcesses | DomainNetwork |
	DomainPersistence | DomainAuthority | DomainFiles | DomainKernel | DomainPackages | DomainWeb | DomainIdentity

// GraphSeed is one object-graph selector, parsed once for the plan, the
// collection and the walk.
type GraphSeed struct {
	Kind  string // unit, pid, path, package
	Value string
}

// Plan is what one run reads. Surfaces selects the startup collectors; a nil
// map derives them from the domains, and an empty non-nil map reads none.
// Units narrows a service run to the named units.
type Plan struct {
	Domains        Domain
	Surfaces       map[string]bool
	Paths          []string
	Exclude        []string
	PIDs           map[int]bool
	Units          map[string]bool
	InventoryRoots []string
	// Seed is the object an object graph grew from, when the run named one.
	// The collector scopes the unit inventory, the process scan and the
	// socket owner scan to it; every other run leaves it zero.
	Seed GraphSeed
}

// seedUnit is the unit an object graph selected, or "" when the seed names
// another kind of object.
func (p Plan) seedUnit() string {
	if p.Seed.Kind == "unit" {
		return p.Seed.Value
	}
	return ""
}

// FullPlan reads every bounded domain. The static inventory walks the program
// directories unless InventoryRoots names other trees.
func FullPlan() Plan {
	return Plan{Domains: AllDomains}
}

// ObjectGraphPlan reads the context one object's graph needs. A unit explains
// itself through systemd, its processes and their sockets; a pid through the
// process table and its sockets; a path or a package may be named by any
// activation surface, so the walk reads them all. The authority walk and the
// static inventory explain no single object, so an object graph stays cheap.
func ObjectGraphPlan(seed GraphSeed) Plan {
	plan := Plan{Domains: DomainBase | DomainServices | DomainProcesses | DomainNetwork | DomainPersistence, Seed: seed}
	switch seed.Kind {
	case "unit":
		plan.Domains = DomainBase | DomainServices | DomainProcesses | DomainNetwork
		plan.Surfaces = map[string]bool{"systemd": true}
	case "pid":
		plan.Domains = DomainBase | DomainProcesses | DomainNetwork
		plan.Surfaces = map[string]bool{}
	default:
		plan.Surfaces = nil
	}
	return plan
}

// Has reports whether the plan selected a domain.
func (p Plan) Has(domain Domain) bool { return p.Domains&domain != 0 }

// startupScope answers which startup collectors the plan turns on. An
// explicit surface set wins; otherwise the registry union of the selected
// domains decides.
func (p Plan) startupScope() startup.Scope {
	if p.Surfaces != nil {
		return startupScopeFor(p.Surfaces)
	}
	var scope startup.Scope
	for _, module := range modules {
		if p.Has(module.Bit) && module.Startup != nil {
			scope = mergeScope(scope, module.Startup())
		}
	}
	return scope
}

// mergeScope unions two startup scopes.
func mergeScope(scope, other startup.Scope) startup.Scope {
	scope.Systemd = scope.Systemd || other.Systemd
	scope.Profile = scope.Profile || other.Profile
	scope.Cron = scope.Cron || other.Cron
	scope.Init = scope.Init || other.Init
	scope.Loader = scope.Loader || other.Loader
	scope.Udev = scope.Udev || other.Udev
	scope.SSH = scope.SSH || other.SSH
	scope.PAM = scope.PAM || other.PAM
	scope.Supervisor = scope.Supervisor || other.Supervisor
	scope.XDG = scope.XDG || other.XDG
	scope.Apt = scope.Apt || other.Apt
	scope.Module = scope.Module || other.Module
	scope.System = scope.System || other.System
	return scope
}

func startupScopeFor(names map[string]bool) startup.Scope {
	var scope startup.Scope
	for name := range names {
		switch name {
		case "systemd":
			scope.Systemd = true
		case "profile":
			scope.Profile = true
		case "cron":
			scope.Cron = true
		case "init":
			scope.Init = true
		case "loader":
			scope.Loader = true
		case "udev":
			scope.Udev = true
		case "ssh":
			scope.SSH = true
		case "pam":
			scope.PAM = true
		case "supervisor":
			scope.Supervisor = true
		case "xdg":
			scope.XDG = true
		case "apt":
			scope.Apt = true
		case "module":
			scope.Module = true
		case "system":
			scope.System = true
		}
	}
	return scope
}

// positivePIDs keeps the included pids of a filter, dropping exclusions.
func positivePIDs(pids map[int]bool) map[int]bool {
	out := map[int]bool{}
	for pid, keep := range pids {
		if keep && pid > 0 {
			out[pid] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
