package audit

// The `show` sections: one table entry per raw inventory, with every name it
// answers to. The table drives the router, the collection plan, the text
// panel and the JSON answer, so a section is one entry and the vocabulary
// cannot drift from what the sections print.

import (
	"reflect"
	"slices"

	"karma/internal/startup"
)

// Section is one `karma show` section.
type Section struct {
	// Words are the names the section answers to; the first is canonical.
	Words []string
	// Panel is the title the section prints under, the same title the
	// audit's evidence block uses for the same inventory.
	Panel string
	// Domains names what the section needs collected beyond the base.
	Domains Domain
	// AllSurfaces reports whether the section reads the scope's activation
	// surfaces; a plan that names none reads every surface.
	AllSurfaces bool
	// SkipEvidence keeps a section out of the audit's EVIDENCE block. The
	// coverage panel is printed by the report itself, after the inventories.
	SkipEvidence bool
	// PIDContext collects the process table when the scope names pids or
	// units, so a trail row can answer its owner without a second /proc pass.
	PIDContext bool
	// Plain marks rows that carry no palette; they are sanitized before a
	// terminal sees them.
	Plain bool
	// Rows builds the section's rows from the run's view. Count overrides the
	// number the panel head prints when the inventory is more than its data
	// length (the process and kernel sections); every other section prints
	// its data length.
	Rows  func(view *View, options RenderOptions) []string
	Count func(view *View, options RenderOptions) int
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
	if s.PIDContext && (len(base.PIDs) > 0 || len(base.Units) > 0 || len(base.ExcludePIDs) > 0 || len(base.ExcludeUnits) > 0) {
		base.Domains |= DomainProcesses
	}
	switch {
	case !s.AllSurfaces:
		base.Surfaces = surfacePtr(0)
	case base.Surfaces == nil:
		// A section that reads every surface still honors the scope's
		// surface exclusions; a hand-built plan with no surface set reads all.
		base.Surfaces = surfacePtr(startup.AllScope())
	}
	return base
}

// sections is the whole `show` vocabulary, in print order.
var sections = []*Section{
	{
		Words:       []string{"activation", "persistence", "boot", "login", "device", "schedule"},
		Panel:       "ACTIVATION",
		Domains:     DomainPersistence,
		AllSurfaces: true,
		Rows:        activationRows,
		JSONKey:     "activations",
		Data:        func(view *View, options RenderOptions) any { return view.Activations },
	},
	{
		Words:   []string{"process", "processes", "activity"},
		Panel:   "PROCESS",
		Domains: DomainProcesses | DomainNetwork,
		Rows:    processRows,
		Count:   processCount,
		JSONKey: "processes",
		Data:    func(view *View, options RenderOptions) any { return view.Processes },
	},
	{
		Words:   []string{"services", "service"},
		Panel:   "SERVICE",
		Domains: DomainServices,
		Rows:    serviceRows,
		JSONKey: "services",
		Data:    func(view *View, options RenderOptions) any { return view.Services },
	},
	{
		Words:   []string{"listeners", "sockets", "listen"},
		Panel:   "LISTEN",
		Domains: DomainProcesses | DomainNetwork,
		Rows:    socketRows,
		JSONKey: "listeners",
		Data:    func(view *View, options RenderOptions) any { return view.Sockets },
	},
	{
		Words:   []string{"connections", "connection", "network"},
		Panel:   "CONNECTION",
		Domains: DomainProcesses | DomainNetwork,
		Rows:    connectionRows,
		JSONKey: "connections",
		Data:    func(view *View, options RenderOptions) any { return view.Connections },
	},
	{
		Words:   []string{"kernel"},
		Panel:   "KERNEL",
		Domains: DomainKernel,
		Rows:    kernelRows,
		Count:   kernelCount,
		JSONKey: "kernel",
		Data:    func(view *View, options RenderOptions) any { return view.Kernel },
	},
	{
		Words:   []string{"authority"},
		Panel:   "AUTHORITY",
		Domains: DomainAuthority,
		Rows:    authorityRows,
		JSONKey: "authority",
		Data:    func(view *View, options RenderOptions) any { return view.Authority },
	},
	{
		Words:   []string{"mounts"},
		Panel:   "MOUNTS",
		Domains: 0,
		Rows:    mountRows,
		JSONKey: "mounts",
		Data:    func(view *View, options RenderOptions) any { return view.Mounts },
	},
	{
		Words:      []string{"trail", "history"},
		Panel:      "TRAIL",
		Domains:    DomainTrail | DomainIdentity,
		PIDContext: true,
		Rows:       trailRows,
		JSONKey:    "trail",
		Data:       func(view *View, options RenderOptions) any { return view.Trail },
	},
	{
		Words:        []string{"coverage"},
		Panel:        "COVERAGE",
		Domains:      AllDomains,
		AllSurfaces:  true,
		SkipEvidence: true,
		Plain:        true,
		Rows: func(view *View, options RenderOptions) []string {
			return coverageRows(reportCoverage(view.Snapshot, options.Filter))
		},
		JSONKey: "coverage",
		Data: func(view *View, options RenderOptions) any {
			return reportCoverage(view.Snapshot, options.Filter)
		},
	},
}

// reportCoverage answers the coverage section's records. Coverage is a
// judgment answer — the module judges append to it as they run — so the
// section reads it through the one Judge pass rather than a second assembly.
func reportCoverage(snapshot *Snapshot, filter Filter) []Coverage {
	return Judge(snapshot, filter).Coverage
}

// coverageRows reads the records as the panel's lines.
func coverageRows(records []Coverage) []string {
	rows := make([]string, 0, len(records))
	for _, record := range records {
		rows = append(rows, record.Detail)
	}
	return rows
}

// count answers the number a panel head prints: the section's override, or
// the length of its machine answer.
func (s *Section) count(view *View, options RenderOptions) int {
	if s.Count != nil {
		return s.Count(view, options)
	}
	if value := reflect.ValueOf(s.Data(view, options)); value.Kind() == reflect.Slice {
		return value.Len()
	}
	return 0
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
	slices.Sort(words)
	return words
}
