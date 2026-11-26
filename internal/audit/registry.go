package audit

// The module registry is the one place a bounded domain is described: its
// word, its bit, the startup surfaces it reads, its collector, its judge, its
// graph and its show panels. The plan grammar, the collection loop, the
// judgment loop, `karma graph`, `karma show` and `karma list` are all derived
// from this table, so a new domain is one entry and the vocabulary cannot
// drift.

import (
	"context"
	"sort"

	"karma/internal/startup"
)

// JudgeFunc judges one domain over a collected snapshot. Report is available
// for the domains that count their own rows.
type JudgeFunc func(snapshot *Snapshot, report *Report, a *assessor, filter Filter, add func(Finding)) []string

// Module is one bounded domain.
type Module struct {
	Name string // the scope word: services, processes, ...
	Bit  Domain
	// Startup is the startup surfaces the domain's collection reads. A domain
	// that reads none leaves it nil.
	Startup func() startup.Scope
	// Collect fills the domain's part of the snapshot and answers coverage.
	Collect func(context.Context, *Snapshot) []string
	// Judge turns the collected state into findings and coverage.
	Judge JudgeFunc
	// Graph draws the domain as relations.
	Graph func(*Snapshot) *Profile
	// GraphWord is the `karma graph` word when it differs from Name.
	GraphWord string
	// Show names the raw inventory sections the domain answers: section word
	// -> panel title, plus the extra domains the section needs collected.
	Show map[string]ShowSpec
}

// ShowSpec is one `show` section: the panel it prints and the domains the
// collector must read for it.
type ShowSpec struct {
	Domain Domain
	Panel  string
}

// modules is the registry, in collection order. A later module may read an
// earlier one's rows (the socket owners read the process table), so the
// order is part of the contract.
var modules = []Module{
	{
		Name: "services", Bit: DomainServices,
		Startup: func() startup.Scope { return startup.Scope{Systemd: true} },
		Collect: func(ctx context.Context, snapshot *Snapshot) []string {
			return collectServicesModule(ctx, snapshot)
		},
		Show: map[string]ShowSpec{"services": {Domain: DomainServices, Panel: "SERVICE"}},
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
		Show: map[string]ShowSpec{
			"process":  {Domain: DomainProcesses | DomainNetwork, Panel: "PROCESS"},
			"activity": {Domain: DomainProcesses | DomainNetwork, Panel: "PROCESS"},
		},
	},
	{
		Name: "network", Bit: DomainNetwork,
		Collect: func(ctx context.Context, snapshot *Snapshot) []string {
			return collectSocketsModule(ctx, snapshot)
		},
		Judge: func(snapshot *Snapshot, report *Report, a *assessor, filter Filter, add func(Finding)) []string {
			judgeConnections(snapshot, filter, add)
			return nil
		},
		Graph: networkGraph,
		Show: map[string]ShowSpec{
			"listeners":   {Domain: DomainProcesses | DomainNetwork, Panel: "LISTEN"},
			"sockets":     {Domain: DomainProcesses | DomainNetwork, Panel: "LISTEN"},
			"listen":      {Domain: DomainProcesses | DomainNetwork, Panel: "LISTEN"},
			"connections": {Domain: DomainProcesses | DomainNetwork, Panel: "CONNECTION"},
			"connection":  {Domain: DomainProcesses | DomainNetwork, Panel: "CONNECTION"},
			"network":     {Domain: DomainProcesses | DomainNetwork, Panel: "CONNECTION"},
		},
	},
	{
		Name: "persistence", Bit: DomainPersistence,
		Startup:   startup.AllScope,
		Judge:     judgeActivations,
		Graph:     bootGraph,
		GraphWord: "boot",
		Show: map[string]ShowSpec{
			"activation":  {Domain: DomainPersistence, Panel: "ACTIVATION"},
			"persistence": {Domain: DomainPersistence, Panel: "ACTIVATION"},
			"boot":        {Domain: DomainPersistence, Panel: "ACTIVATION"},
			"login":       {Domain: DomainPersistence, Panel: "ACTIVATION"},
			"service":     {Domain: DomainPersistence, Panel: "ACTIVATION"},
			"device":      {Domain: DomainPersistence, Panel: "ACTIVATION"},
			"schedule":    {Domain: DomainPersistence, Panel: "ACTIVATION"},
		},
	},
	{
		Name: "authority", Bit: DomainAuthority,
		Collect: func(ctx context.Context, snapshot *Snapshot) []string {
			return collectAuthorityModule(ctx, snapshot)
		},
		Judge: judgeAuthority,
		Graph: authorityGraph,
		Show:  map[string]ShowSpec{"authority": {Domain: DomainAuthority, Panel: "AUTHORITY"}},
	},
	{
		Name: "files", Bit: DomainFiles,
		Collect: func(ctx context.Context, snapshot *Snapshot) []string {
			return collectInventory(ctx, snapshot, snapshot.plan)
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
			return collectKernel(ctx, snapshot, snapshot.classify, snapshot.ownedAll)
		},
		Judge: func(snapshot *Snapshot, report *Report, a *assessor, filter Filter, add func(Finding)) []string {
			return judgeKernel(snapshot, a, filter, add)
		},
		Graph: kernelGraph,
		Show:  map[string]ShowSpec{"kernel": {Domain: DomainKernel, Panel: "KERNEL"}},
	},
	{
		Name: "packages", Bit: DomainPackages,
		Collect: collectPackages,
		Judge: func(snapshot *Snapshot, report *Report, a *assessor, filter Filter, add func(Finding)) []string {
			return judgePackages(snapshot, filter, add)
		},
		Graph: packageGraph,
	},
	{
		Name: "web", Bit: DomainWeb,
		Collect: func(ctx context.Context, snapshot *Snapshot) []string {
			return collectWeb(ctx, snapshot, snapshot.classify, snapshot.ownedAll)
		},
		Judge: func(snapshot *Snapshot, report *Report, a *assessor, filter Filter, add func(Finding)) []string {
			return judgeWeb(snapshot, a, filter, add)
		},
		Graph: webGraph,
	},
	{
		Name: "identity", Bit: DomainIdentity,
		Collect: func(ctx context.Context, snapshot *Snapshot) []string {
			return collectIdentity(ctx, snapshot, snapshot.classify, snapshot.ownedAll)
		},
		Judge: func(snapshot *Snapshot, report *Report, a *assessor, filter Filter, add func(Finding)) []string {
			return judgeIdentity(snapshot, a, filter, add)
		},
		Graph: identityGraph,
	},
}

// Modules returns the registry in collection order.
func Modules() []Module { return modules }

// ModuleForWord answers the module a scope word selects.
func ModuleForWord(word string) (Module, bool) { return moduleByWord(word) }

// moduleByWord answers the module a scope word selects.
func moduleByWord(word string) (Module, bool) {
	for _, module := range modules {
		if module.Name == word {
			return module, true
		}
	}
	return Module{}, false
}

// moduleByGraphWord answers the module a `karma graph` word selects.
func moduleByGraphWord(word string) (Module, bool) {
	for _, module := range modules {
		name := module.GraphWord
		if name == "" {
			name = module.Name
		}
		if name == word && module.Graph != nil {
			return module, true
		}
	}
	return Module{}, false
}

// moduleByShowWord answers the module a `karma show` word selects, with the
// section spec.
func moduleByShowWord(word string) (Module, ShowSpec, bool) {
	for _, module := range modules {
		if spec, ok := module.Show[word]; ok {
			return module, spec, true
		}
	}
	return Module{}, ShowSpec{}, false
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
		if module.Graph == nil {
			continue
		}
		name := module.GraphWord
		if name == "" {
			name = module.Name
		}
		words = append(words, name)
	}
	return words
}

// IsGraphWord answers whether a word names a relation domain `graph` draws.
func IsGraphWord(word string) bool {
	for _, module := range modules {
		if module.Graph == nil {
			continue
		}
		name := module.GraphWord
		if name == "" {
			name = module.Name
		}
		if name == word {
			return true
		}
	}
	return false
}

// IsShowWord answers whether a word names a show section.
func IsShowWord(word string) bool {
	if word == "coverage" || word == "mounts" {
		return true
	}
	_, _, ok := moduleByShowWord(word)
	return ok
}

// ShowWords lists the `karma show` words, sorted.
func ShowWords() []string {
	var words []string
	for _, module := range modules {
		for word := range module.Show {
			words = append(words, word)
		}
	}
	words = append(words, "coverage", "mounts")
	sort.Strings(words)
	return words
}

// GraphPlan reads only the domains one graph word needs.
func GraphPlan(word string) (Plan, bool) {
	module, ok := moduleByGraphWord(word)
	if !ok {
		return Plan{}, false
	}
	plan := Plan{Domains: DomainBase | module.Bit}
	if module.Bit&DomainNetwork != 0 {
		plan.Domains |= DomainProcesses
	}
	if module.Name == "persistence" {
		// The boot graph reads every activation surface, not only the ones
		// the selected domains' collectors read.
		plan.Surfaces = nil
	} else {
		plan.Surfaces = map[string]bool{}
	}
	return plan, true
}

// ShowPlan reads the domains one show section needs. The section's module
// answers first; the spec may add domains, and coverage is the full host.
func ShowPlan(word string, base Plan) (Plan, bool) {
	if word == "coverage" {
		return FullPlan(), true
	}
	if word == "mounts" {
		base.Domains = DomainBase
		base.Surfaces = map[string]bool{}
		return base, true
	}
	module, spec, ok := moduleByShowWord(word)
	if !ok {
		return Plan{}, false
	}
	base.Domains = DomainBase | module.Bit | spec.Domain
	base.Surfaces = map[string]bool{}
	if module.Bit == DomainPersistence {
		base.Surfaces = nil
	}
	return base, true
}
