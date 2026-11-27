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

// JudgeFunc judges one domain over a collected snapshot and answers the
// domain's coverage records.
type JudgeFunc func(*judgePass) []Coverage

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
	// ScopeNeeds names the domains a pid or unit scope adds to a selected
	// module's collection, so a scoped module still sees its owning rows: a
	// trail row's owner is a process, whatever the scope judged.
	ScopeNeeds Domain
	// Collect fills the domain's part of the snapshot and answers coverage.
	Collect func(context.Context, *Snapshot) []Coverage
	// Judge turns the collected state into findings and coverage.
	Judge JudgeFunc
	// GraphBuilder draws the domain as relations.
	GraphBuilder *GraphSpec
}

// modules is the registry, in collection order. A later module may read an
// earlier one's rows (the socket owners read the process table); init sorts
// the table by Needs, so the order stays correct when entries move.
var modules = orderModules([]Module{
	{
		Name: "services", Bit: DomainServices, Selects: DomainPersistence,
		Startup: func() startup.Scope { return startup.Systemd },
		Collect: collectServicesModule,
	},
	{
		Name:    "processes",
		Bit:     DomainProcesses,
		Collect: collectProcessesModule,
		Judge:   judgeProcesses,
	},
	{
		Name:    "network",
		Bit:     DomainNetwork,
		Needs:   DomainProcesses,
		Collect: collectSocketsModule,
		Judge:   judgeConnections,
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
		Name:         "authority",
		Bit:          DomainAuthority,
		Collect:      collectAuthorityModule,
		Judge:        judgeAuthority,
		GraphBuilder: &GraphSpec{Domain: DomainAuthority, Build: authorityGraph},
	},
	{
		Name:    "files",
		Bit:     DomainFiles,
		Collect: collectFiles,
		Judge:   judgeFiles,
	},
	{
		Name:         "kernel",
		Bit:          DomainKernel,
		Collect:      collectKernel,
		Judge:        judgeKernel,
		GraphBuilder: &GraphSpec{Domain: DomainKernel, Build: kernelGraph},
	},
	{
		Name:         "packages",
		Bit:          DomainPackages,
		Collect:      collectPackages,
		Judge:        judgePackages,
		GraphBuilder: &GraphSpec{Domain: DomainPackages, Build: packageGraph},
	},
	{
		Name:         "web",
		Bit:          DomainWeb,
		Collect:      collectWeb,
		Judge:        judgeWeb,
		GraphBuilder: &GraphSpec{Domain: DomainWeb, Build: webGraph},
	},
	{
		Name:         "identity",
		Bit:          DomainIdentity,
		Collect:      collectIdentity,
		Judge:        judgeIdentity,
		GraphBuilder: &GraphSpec{Domain: DomainIdentity, Build: identityGraph},
	},
	{
		Name:       "trail",
		Bit:        DomainTrail,
		Needs:      DomainIdentity,
		ScopeNeeds: DomainProcesses,
		Collect:    collectTrail,
	},
})

// orderModules stable-sorts the registry so every module's Needs are collected
// before it runs. Declaration order breaks ties, so a table that already
// satisfies its dependencies keeps its vocabulary order.
func orderModules(in []Module) []Module {
	ordered := make([]Module, 0, len(in))
	placed := make([]bool, len(in))
	have := Domain(0)
	for {
		progressed := false
		for index, module := range in {
			if placed[index] || module.Needs&^have != 0 {
				continue
			}
			ordered = append(ordered, module)
			placed[index] = true
			have |= module.Bit
			progressed = true
		}
		if !progressed {
			break
		}
	}
	// A cycle keeps the declaration order rather than dropping a module.
	for index, module := range in {
		if !placed[index] {
			ordered = append(ordered, module)
		}
	}
	return ordered
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

// off names the bounded domains the set leaves out, in registry order.
func (d Domain) off() []string {
	var off []string
	for _, module := range modules {
		if d&module.Bit == 0 {
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
