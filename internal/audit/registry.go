package audit

// The module registry is the one place a bounded domain is described: its
// word, its bit, the startup surfaces it reads, its collector, its judge and
// its relation graph. The plan grammar, the collection loop, the judgment
// loop and `karma graph` are all derived from this table, so a new domain is
// one entry and the vocabulary cannot drift. The `karma show` sections have
// their own table in sections.go, one entry per raw inventory.

import (
	"context"

	"karma/internal/startup"
)

// JudgeFunc judges one domain over a collected snapshot. Report is available
// for the domains that count their own rows.
type JudgeFunc func(snapshot *Snapshot, report *Report, a *assessor, filter Filter, add func(Finding)) []string

// GraphSpec is the relation graph a domain draws: the word it answers to,
// the findings it shows, what its collection needs, and the builder.
type GraphSpec struct {
	// Word is the `karma graph` word when it differs from the module's name.
	Word string
	// Domain is the finding set the graph shows; the plan reads the same set.
	Domain Domain
	// AllSurfaces reports whether the graph reads every activation surface
	// rather than the module's own selection.
	AllSurfaces bool
	// Build draws the graph from a collected snapshot.
	Build func(*Snapshot) *GraphView
}

// Plan reads the domains one domain graph needs.
func (s *GraphSpec) Plan(bit Domain) Plan {
	plan := Plan{Filter: Filter{Domains: DomainBase | bit | s.Domain}}
	if s.AllSurfaces {
		plan.Surfaces = surfacePtr(startup.AllScope())
	} else {
		plan.Surfaces = surfacePtr(0)
	}
	return plan
}

// Module is one bounded domain.
type Module struct {
	Name string // the scope word: services, processes, ...
	Bit  Domain
	// Selects is the extra domain set a positive scope word turns on. A
	// services audit also judges the activation edges that launch a unit.
	Selects Domain
	// Startup is the startup surfaces the domain's collection reads. A domain
	// that reads none leaves it nil.
	Startup func() startup.Scope
	// Needs names the domains whose collected rows this domain reads as
	// context. They are collected but not judged; a network finding can use
	// the process table without turning a processes audit into this one.
	Needs Domain
	// Collect fills the domain's part of the snapshot and answers coverage.
	Collect func(context.Context, *Snapshot) []string
	// Judge turns the collected state into findings and coverage.
	Judge JudgeFunc
	// GraphBuilder draws the domain as relations.
	GraphBuilder *GraphSpec
}

// modules is the registry, in collection order. A later module may read an
// earlier one's rows (the socket owners read the process table), so the
// order is part of the contract.
var modules = []Module{
	{
		Name: "services", Bit: DomainServices, Selects: DomainPersistence,
		Startup: func() startup.Scope { return startup.Systemd },
		Collect: func(ctx context.Context, snapshot *Snapshot) []string {
			return collectServicesModule(ctx, snapshot)
		},
	},
	{
		Name: "processes", Bit: DomainProcesses,
		Collect: func(ctx context.Context, snapshot *Snapshot) []string {
			return collectProcessesModule(ctx, snapshot)
		},
		Judge: func(snapshot *Snapshot, report *Report, a *assessor, filter Filter, add func(Finding)) []string {
			judgeLoaders(snapshot, a, filter, add)
			return nil
		},
	},
	{
		Name: "network", Bit: DomainNetwork,
		Needs: DomainProcesses,
		Collect: func(ctx context.Context, snapshot *Snapshot) []string {
			return collectSocketsModule(ctx, snapshot)
		},
		Judge: func(snapshot *Snapshot, report *Report, a *assessor, filter Filter, add func(Finding)) []string {
			judgeConnections(snapshot, filter, add)
			return nil
		},
		GraphBuilder: &GraphSpec{
			Domain: DomainProcesses | DomainNetwork,
			Build:  networkGraph,
		},
	},
	{
		Name:    "persistence",
		Bit:     DomainPersistence,
		Startup: startup.AllScope,
		Judge:   judgeActivations,
		GraphBuilder: &GraphSpec{
			Word:        "boot",
			Domain:      DomainPersistence,
			AllSurfaces: true,
			Build:       bootGraph,
		},
	},
	{
		Name: "authority", Bit: DomainAuthority,
		Collect: func(ctx context.Context, snapshot *Snapshot) []string {
			return collectAuthorityModule(ctx, snapshot)
		},
		Judge:        judgeAuthority,
		GraphBuilder: &GraphSpec{Domain: DomainAuthority, Build: authorityGraph},
	},
	{
		Name: "files", Bit: DomainFiles,
		Collect: func(ctx context.Context, snapshot *Snapshot) []string {
			return collectFiles(ctx, snapshot, snapshot.plan)
		},
		Judge: func(snapshot *Snapshot, report *Report, a *assessor, filter Filter, add func(Finding)) []string {
			for _, finding := range unownedFindings(snapshot, a, filter) {
				add(finding)
			}
			return nil
		},
	},
	{
		Name: "kernel", Bit: DomainKernel,
		Collect: func(ctx context.Context, snapshot *Snapshot) []string {
			return collectKernel(ctx, snapshot, snapshot.classify)
		},
		Judge: func(snapshot *Snapshot, report *Report, a *assessor, filter Filter, add func(Finding)) []string {
			return judgeKernel(snapshot, a, filter, add)
		},
		GraphBuilder: &GraphSpec{Domain: DomainKernel, Build: kernelGraph},
	},
	{
		Name: "packages", Bit: DomainPackages,
		Collect: collectPackages,
		Judge: func(snapshot *Snapshot, report *Report, a *assessor, filter Filter, add func(Finding)) []string {
			return judgePackages(snapshot, filter, add)
		},
		GraphBuilder: &GraphSpec{Domain: DomainPackages, Build: packageGraph},
	},
	{
		Name: "web", Bit: DomainWeb,
		Collect: func(ctx context.Context, snapshot *Snapshot) []string {
			return collectWeb(ctx, snapshot, snapshot.classify)
		},
		Judge: func(snapshot *Snapshot, report *Report, a *assessor, filter Filter, add func(Finding)) []string {
			return judgeWeb(snapshot, a, filter, add)
		},
		GraphBuilder: &GraphSpec{Domain: DomainWeb, Build: webGraph},
	},
	{
		Name: "identity", Bit: DomainIdentity,
		Collect: func(ctx context.Context, snapshot *Snapshot) []string {
			return collectIdentity(ctx, snapshot, snapshot.classify)
		},
		Judge: func(snapshot *Snapshot, report *Report, a *assessor, filter Filter, add func(Finding)) []string {
			return judgeIdentity(snapshot, a, filter, add)
		},
		GraphBuilder: &GraphSpec{Domain: DomainIdentity, Build: identityGraph},
	},
	{
		Name: "trail", Bit: DomainTrail,
		Needs: DomainIdentity,
		Collect: func(ctx context.Context, snapshot *Snapshot) []string {
			return collectTrail(ctx, snapshot)
		},
	},
}

// Modules returns a copy of the registry in collection order.
func Modules() []Module { return append([]Module(nil), modules...) }

// ModuleForWord answers the module a scope word selects.
func ModuleForWord(word string) (Module, bool) {
	for _, module := range modules {
		if module.Name == word {
			return module, true
		}
	}
	return Module{}, false
}

// GraphTarget answers the module and the graph a `karma graph` word selects.
func GraphTarget(word string) (Module, *GraphSpec, bool) {
	for _, module := range modules {
		spec := module.GraphBuilder
		if spec == nil {
			continue
		}
		name := spec.Word
		if name == "" {
			name = module.Name
		}
		if name == word {
			return module, spec, true
		}
	}
	return Module{}, nil, false
}

// OffDomains names the bounded domains a run did not judge, in registry order.
// It reads the same domain set the judges and the views read.
func OffDomains(domains Domain) []string {
	if domains == 0 || domains == AllDomains {
		return nil
	}
	var off []string
	for _, module := range modules {
		if domains&module.Bit == 0 {
			off = append(off, module.Name)
		}
	}
	return off
}

// DomainWords lists the scope words in registry order.
func DomainWords() []string {
	words := make([]string, 0, len(modules))
	for _, module := range Modules() {
		words = append(words, module.Name)
	}
	return words
}

// GraphWords lists the `karma graph` words in registry order.
func GraphWords() []string {
	var words []string
	for _, module := range modules {
		if module.GraphBuilder == nil {
			continue
		}
		name := module.GraphBuilder.Word
		if name == "" {
			name = module.Name
		}
		words = append(words, name)
	}
	return words
}
