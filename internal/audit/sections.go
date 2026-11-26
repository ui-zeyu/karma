package audit

// The `show` sections: one table entry per raw inventory, with every name it
// answers to. The table drives the router, the collection plan, the text
// panel and the JSON answer, so a section is one entry and the vocabulary
// cannot drift from what the sections print.

import "sort"

// Section is one `karma show` section.
type Section struct {
	// Words are the names the section answers to; the first is canonical.
	Words []string
	// Panel is the title the section prints under, the same title the
	// audit's evidence block uses for the same inventory.
	Panel string
	// Domains names what the section needs collected beyond the base.
	Domains Domain
	// AllSurfaces reports whether the section reads every activation
	// surface rather than the scope's own selection.
	AllSurfaces bool
	// Rows builds the section's rows from the run's view. The function
	// answers the rows and the count the panel head prints.
	Rows func(view *View, options RenderOptions) ([]string, func(int) int)
	// JSONKey and Data are the section's machine-readable answer: the key
	// the section's collected structures travel under.
	JSONKey string
	Data    func(view *View, options RenderOptions) any
}

// HasWord answers whether the section answers to a word.
func (s *Section) HasWord(word string) bool {
	for _, name := range s.Words {
		if name == word {
			return true
		}
	}
	return false
}

// Plan folds the section's needs into a scope's plan. The section decides
// the domains and the surfaces; the scope keeps its units, pids and paths.
func (s *Section) Plan(base Plan) Plan {
	base.Domains = DomainBase | s.Domains
	if s.AllSurfaces {
		base.Surfaces = nil
	} else {
		base.Surfaces = map[string]bool{}
	}
	return base
}

// sections is the whole `show` vocabulary, in print order.
var sections = []*Section{
	{
		Words:       []string{"activation", "persistence", "boot", "login", "service", "device", "schedule"},
		Panel:       "ACTIVATION",
		Domains:     DomainPersistence,
		AllSurfaces: true,
		Rows: func(view *View, options RenderOptions) ([]string, func(int) int) {
			return activationRows(view, options), activationCount
		},
		JSONKey: "activations",
		Data:    func(view *View, options RenderOptions) any { return view.Activations },
	},
	{
		Words:   []string{"process", "activity"},
		Panel:   "PROCESS",
		Domains: DomainProcesses | DomainNetwork,
		Rows: func(view *View, options RenderOptions) ([]string, func(int) int) {
			return processRows(view, options), headerless
		},
		JSONKey: "processes",
		Data:    func(view *View, options RenderOptions) any { return view.Processes },
	},
	{
		Words:   []string{"services"},
		Panel:   "SERVICE",
		Domains: DomainServices,
		Rows: func(view *View, options RenderOptions) ([]string, func(int) int) {
			return serviceRows(view, options), headerless
		},
		JSONKey: "services",
		Data:    func(view *View, options RenderOptions) any { return view.Services },
	},
	{
		Words:   []string{"listeners", "sockets", "listen"},
		Panel:   "LISTEN",
		Domains: DomainProcesses | DomainNetwork,
		Rows: func(view *View, options RenderOptions) ([]string, func(int) int) {
			return socketRows(view, options), headerless
		},
		JSONKey: "listeners",
		Data:    func(view *View, options RenderOptions) any { return view.Sockets },
	},
	{
		Words:   []string{"connections", "connection", "network"},
		Panel:   "CONNECTION",
		Domains: DomainProcesses | DomainNetwork,
		Rows: func(view *View, options RenderOptions) ([]string, func(int) int) {
			return connectionRows(view, options), headerless
		},
		JSONKey: "connections",
		Data:    func(view *View, options RenderOptions) any { return view.Connections },
	},
	{
		Words:   []string{"kernel"},
		Panel:   "KERNEL",
		Domains: DomainKernel,
		Rows: func(view *View, options RenderOptions) ([]string, func(int) int) {
			return kernelRows(view, options), headerless
		},
		JSONKey: "kernel",
		Data:    func(view *View, options RenderOptions) any { return view.Kernel },
	},
	{
		Words:   []string{"authority"},
		Panel:   "AUTHORITY",
		Domains: DomainAuthority,
		Rows: func(view *View, options RenderOptions) ([]string, func(int) int) {
			return authorityRows(view, options), headerless
		},
		JSONKey: "authority",
		Data:    func(view *View, options RenderOptions) any { return view.Authority },
	},
	{
		Words:   []string{"mounts"},
		Panel:   "MOUNTS",
		Domains: 0,
		Rows: func(view *View, options RenderOptions) ([]string, func(int) int) {
			return mountRows(view, options), headerless
		},
		JSONKey: "mounts",
		Data:    func(view *View, options RenderOptions) any { return view.Mounts },
	},
	{
		Words:       []string{"coverage"},
		Panel:       "COVERAGE",
		Domains:     AllDomains,
		AllSurfaces: true,
		Rows: func(view *View, options RenderOptions) ([]string, func(int) int) {
			coverage := Judge(view.Snapshot, options.Filter).Coverage
			return coverage, func(rows int) int { return rows }
		},
		JSONKey: "coverage",
		Data: func(view *View, options RenderOptions) any {
			return Judge(view.Snapshot, options.Filter).Coverage
		},
	},
}

// SectionFor answers the section a `karma show` word selects.
func SectionFor(word string) (*Section, bool) {
	for _, section := range sections {
		if section.HasWord(word) {
			return section, true
		}
	}
	return nil, false
}

// ShowWords lists every `karma show` word, sorted.
func ShowWords() []string {
	var words []string
	for _, section := range sections {
		words = append(words, section.Words...)
	}
	sort.Strings(words)
	return words
}
