package audit

// Filter is the one scope state a run carries: the domains, an explicit
// startup surface set, and the path/pid/unit selections. This file is the one
// home of its predicates — the view's projections and every judge's row
// filter call the same functions, so a row and its finding cannot answer to
// two different scopes.

import (
	"karma/internal/startup"
	"karma/internal/trust"
)

type Filter struct {
	Domains      Domain
	Surfaces     *startup.Scope // nil means every startup surface
	Paths        []string
	ExcludePaths []string
	PIDs         map[int]bool // positive pids only
	ExcludePIDs  map[int]bool
	Units        map[string]bool // positive units only
	ExcludeUnits map[string]bool
}

// domains resolves the zero value to the full set. The convention keeps a
// hand-built filter in a test on the same path as a bare run; every reader
// of the set goes through here, so the sentinel has one home.
func (f Filter) domains() Domain {
	if f.Domains == 0 {
		return AllDomains
	}
	return f.Domains
}

// pathInScope answers whether one path answers to the scope: inside a
// positive path and outside every exclusion. The three prefix questions
// share one primitive, trust.Under, so the walk pushdown in plan.go and the
// row filters here cannot drift.
func pathInScope(path string, filter Filter) bool {
	if path == "" {
		return len(filter.Paths) == 0
	}
	return !filter.pathExcluded(path) && filter.pathIncluded(path)
}

func (f Filter) pathIncluded(path string) bool {
	if len(f.Paths) == 0 {
		return true
	}
	for _, root := range f.Paths {
		if trust.Under(path, root) {
			return true
		}
	}
	return false
}

func (f Filter) pathExcluded(path string) bool {
	for _, root := range f.ExcludePaths {
		if trust.Under(path, root) {
			return true
		}
	}
	return false
}

// pathOrRealInScope asks the question of a path and its resolved spelling,
// so a usrmerged path answers under either name.
func pathOrRealInScope(path, real string, filter Filter) bool {
	if pathInScope(path, filter) {
		return true
	}
	return real != "" && real != path && pathInScope(real, filter)
}

// touchesPath reports whether a walk rooted at path can answer the scope: a
// positive path is equal, below or above the root, and an excluded root is
// skipped. It is the pushdown every tree walk uses, so a path audit does not
// pay for unrelated trees.
func (f Filter) touchesPath(path string) bool {
	if path == "" || f.pathExcluded(path) {
		return false
	}
	if path == "/" || len(f.Paths) == 0 {
		return true
	}
	for _, root := range f.Paths {
		if trust.Under(path, root) || trust.Under(root, path) {
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

func (f Filter) hasPIDScope() bool {
	return len(f.PIDs) > 0 || len(f.ExcludePIDs) > 0
}

func (f Filter) hasUnitScope() bool {
	return len(f.Units) > 0 || len(f.ExcludeUnits) > 0
}

// pidAllowed reads the positive pid scope and its exclusions. An
// exclusion-only scope is a complement: it removes pids from an otherwise
// whole table.
func (f Filter) pidAllowed(pid int) bool {
	if len(f.PIDs) > 0 {
		return f.PIDs[pid] && !f.ExcludePIDs[pid]
	}
	return !f.ExcludePIDs[pid]
}

// processInScope is the one scope answer for a process. A selected pid is in
// scope by name; otherwise the unit and path selections must name the
// process's unit, image, script or working directory.
func processInScope(process Process, filter Filter) bool {
	if !filter.pidAllowed(process.PID) || !unitAllowed(process.Unit, filter) {
		return false
	}
	if len(filter.PIDs) > 0 {
		return true
	}
	if len(filter.Paths) > 0 {
		return pathInScope(process.Exe, filter) || pathInScope(process.Script, filter) || pathInScope(process.Cwd, filter)
	}
	return true
}

// unitMatches answers the unit half of a collected row: a scope with no unit
// selection keeps every row.
func unitMatches(unit string, units map[string]bool) bool {
	if len(units) == 0 {
		return true
	}
	if units[unit] || units[templateUnit(unit)] {
		return true
	}
	for wanted := range units {
		if templateUnit(unit) == templateUnit(wanted) {
			return true
		}
	}
	return false
}

// unitAllowed reads the positive unit scope and its exclusions. An exclusion
// alone narrows one unit; it never turns the whole unit inventory off.
func unitAllowed(unit string, filter Filter) bool {
	template := templateUnit(unit)
	if filter.ExcludeUnits[unit] || filter.ExcludeUnits[template] {
		return false
	}
	if len(filter.Units) == 0 {
		return true
	}
	return filter.Units[unit] || filter.Units[template]
}

// unitInScope asks the unit question of an activation trigger, whose file
// may be a drop-in of its unit.
func unitInScope(trigger string, filter Filter) bool {
	return unitAllowed(activationUnit(trigger), filter)
}

// surfaceInScope reads the explicit surface selection; nil means every
// startup surface.
func surfaceInScope(surface startup.Surface, filter Filter) bool {
	if filter.Surfaces == nil {
		return true
	}
	return filter.Surfaces.Has(surface)
}

// activationInScope is the one scope answer for an activation edge: the
// surface narrows it, the trigger's unit narrows it, a path exclusion on
// either end removes it, and a positive path scope names one end.
func activationInScope(edge startup.Edge, filter Filter) bool {
	if !surfaceInScope(edge.Surface, filter) || !unitInScope(edge.Trigger, filter) {
		return false
	}
	if filter.pathExcluded(edge.Trigger) || filter.pathExcluded(edge.Target) {
		return false
	}
	if len(filter.Paths) > 0 && !pathInScope(edge.Trigger, filter) && !pathInScope(edge.Target, filter) {
		return false
	}
	return true
}
