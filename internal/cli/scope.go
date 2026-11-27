package cli

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"karma/internal/audit"
	"karma/internal/startup"
)

// scope is the positional narrowing: domains, activation surfaces, paths,
// pids and unit names. It keeps positive and excluded sets apart, so an
// exclusion removes one relation instead of turning a whole domain off.
type scope struct {
	domains         audit.Domain
	excludedDomains audit.Domain

	surfaces        startup.Scope
	useSurfaces     bool
	excludedSurface startup.Scope

	paths       []string
	exclude     []string
	pids        map[int]bool
	excludePIDs map[int]bool
	units       map[string]bool
	excludeUnit map[string]bool
}

// surfaceWords are the startup surfaces. Domain and group words are listed in
// their own panels; the grammar resolves them before this table.
var surfaceWords = startup.SurfaceWords()

// groupScope is one surface group's two effects: the domains it turns on and
// the startup surfaces it reads. excludedDomains applies only when the group
// is negated, which is how !activity removes the activity domains while !boot
// leaves persistence on and removes only its surfaces.
type groupScope struct {
	domains         audit.Domain
	excludedDomains audit.Domain
	surfaces        []string
}

var groups = map[string]groupScope{
	"persistence": {domains: audit.DomainPersistence, surfaces: startup.SurfaceWords()},
	"boot":        {domains: audit.DomainPersistence, surfaces: startup.GroupWords("boot")},
	"login":       {domains: audit.DomainPersistence, surfaces: startup.GroupWords("login")},
	"schedule":    {domains: audit.DomainPersistence, surfaces: startup.GroupWords("schedule")},
	"service": {domains: audit.DomainServices | audit.DomainPersistence,
		surfaces: startup.GroupWords("service")},
	"device":   {domains: audit.DomainPersistence, surfaces: startup.GroupWords("device")},
	"activity": {domains: audit.DomainProcesses | audit.DomainNetwork, excludedDomains: audit.DomainProcesses | audit.DomainNetwork},
}

// groupWords lists the surface groups, sorted, so the vocabulary has one
// canonical order.
func groupWords() []string { return slices.Sorted(maps.Keys(groups)) }

// domainWords is derived from the audit registry, so the CLI vocabulary and
// the collection/judgment table cannot drift. The registry is static, so the
// map is built once.
var domainWords = sync.OnceValue(func() map[string]audit.Domain {
	words := map[string]audit.Domain{}
	for _, word := range audit.DomainWords() {
		if module, ok := audit.ModuleForWord(word); ok {
			words[word] = module.Bit
		}
	}
	return words
})

func parseScope(words []string) (scope, error) {
	parsed := scope{}
	for _, word := range words {
		excluded := strings.HasPrefix(word, "!")
		name := strings.TrimPrefix(word, "!")
		if name == "" {
			return scope{}, fmt.Errorf("an exclusion needs a word after \"!\"")
		}
		if domain, ok := domainWords()[name]; ok {
			parsed.addDomain(name, domain, excluded)
			continue
		}
		if strings.HasPrefix(name, "/proc/") {
			if err := parsed.addPID(strings.TrimPrefix(name, "/proc/"), excluded); err != nil {
				return scope{}, err
			}
			continue
		}
		if isScopePath(name) {
			path, err := cleanScopePath(name)
			if err != nil {
				return scope{}, err
			}
			if excluded {
				parsed.exclude = append(parsed.exclude, path)
			} else {
				parsed.paths = append(parsed.paths, path)
			}
			continue
		}
		if startup.IsUnitName(name) {
			if excluded {
				if parsed.excludeUnit == nil {
					parsed.excludeUnit = map[string]bool{}
				}
				parsed.excludeUnit[name] = true
			} else {
				if parsed.units == nil {
					parsed.units = map[string]bool{}
				}
				parsed.units[name] = true
				parsed.domains |= audit.DomainServices | audit.DomainPersistence |
					audit.DomainProcesses | audit.DomainNetwork
				parsed.addSurfaces([]string{"systemd"})
			}
			continue
		}
		if group, ok := groups[name]; ok {
			parsed.addGroup(group, excluded)
			continue
		}
		if slices.Contains(startup.SurfaceWords(), name) {
			if excluded {
				parsed.excludedSurface |= startup.ScopeForWords([]string{name})
			} else {
				parsed.domains |= audit.DomainPersistence
				if name == "systemd" {
					parsed.domains |= audit.DomainServices
				}
				parsed.addSurfaces([]string{name})
			}
			continue
		}
		return scope{}, fmt.Errorf("unknown scope %q (surfaces: %s)", name, strings.Join(surfaceWords, ", "))
	}
	return parsed, nil
}

// addDomain applies one domain word. services and persistence carry a surface
// requirement: the services inventory also judges the systemd activation
// files, and a persistence audit reads every surface. Excluding services
// drops only its inventory; persistence keeps its own surfaces.
func (s *scope) addDomain(name string, domain audit.Domain, excluded bool) {
	if excluded {
		// Excluding services drops the inventory; persistence keeps its own
		// judgment of systemd files.
		s.excludedDomains |= domain
		return
	}
	module, ok := audit.ModuleForWord(name)
	if !ok {
		s.domains |= domain
		return
	}
	s.domains |= module.Bit | module.Selects
	if module.Startup != nil {
		s.addSurfaceScope(module.Startup())
	}
}

func (s *scope) addSurfaceScope(scope startup.Scope) {
	if scope == 0 {
		return
	}
	s.useSurfaces = true
	s.surfaces |= scope
}

func (s *scope) addGroup(group groupScope, excluded bool) {
	if excluded {
		s.excludedDomains |= group.excludedDomains
		s.excludedSurface |= startup.ScopeForWords(group.surfaces)
		return
	}
	s.domains |= group.domains
	if len(group.surfaces) > 0 {
		s.addSurfaces(group.surfaces)
	}
}

func (s *scope) addSurfaces(names []string) {
	if len(names) == 0 {
		return
	}
	s.useSurfaces = true
	s.surfaces |= startup.ScopeForWords(names)
}

func (s *scope) addPID(value string, excluded bool) error {
	pid, err := strconv.Atoi(value)
	if err != nil || pid <= 0 {
		return fmt.Errorf("unknown process %q", "/proc/"+value)
	}
	if excluded {
		if s.excludePIDs == nil {
			s.excludePIDs = map[int]bool{}
		}
		s.excludePIDs[pid] = true
		return nil
	}
	if s.pids == nil {
		s.pids = map[int]bool{}
	}
	s.pids[pid] = true
	return nil
}

func isScopePath(name string) bool {
	return strings.HasPrefix(name, "/") || strings.HasPrefix(name, "./") ||
		strings.HasPrefix(name, "../") || strings.HasPrefix(name, "~/")
}

// cleanScopePath resolves the relative forms the grammar accepts. Facts are
// absolute, so accepting ./ or ~/ without expanding them would select nothing.
func cleanScopePath(name string) (string, error) {
	switch {
	case strings.HasPrefix(name, "~/"):
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", fmt.Errorf("cannot resolve %q: no home directory", name)
		}
		return filepath.Clean(filepath.Join(home, strings.TrimPrefix(name, "~/"))), nil
	case strings.HasPrefix(name, "./"), strings.HasPrefix(name, "../"):
		path, err := filepath.Abs(name)
		if err != nil {
			return "", fmt.Errorf("cannot resolve %q: %v", name, err)
		}
		return path, nil
	}
	return filepath.Clean(name), nil
}

// plan turns the parsed selection into the one range state the collectors,
// the judges and the views read. A bare run keeps every domain and the
// registry's startup surfaces; positive surface words win, and exclusions are
// applied last so the result does not depend on word order.
func (s scope) plan() audit.Plan {
	paths := s.paths
	rootPath := slices.Contains(paths, "/")
	if rootPath {
		// The root prefix covers every path; keeping it as a positive filter
		// would also suppress the host-level checks. A root path is the bare
		// run, with any exclusions still applied.
		paths = nil
	}
	domains := s.domains
	if domains == 0 {
		switch {
		case rootPath:
			domains = audit.AllDomains
		case len(paths) > 0:
			domains = audit.PathDomains(paths)
		case len(s.pids) > 0:
			domains = audit.DomainProcesses | audit.DomainNetwork
		default:
			domains = audit.AllDomains
		}
	}
	if len(s.pids) > 0 {
		// A pid names a process slice even when a path also narrows the
		// file side of the run.
		domains |= audit.DomainProcesses | audit.DomainNetwork
	}
	domains |= audit.DomainBase
	domains &^= s.excludedDomains

	surfaces := s.surfaces
	if !s.useSurfaces {
		surfaces = audit.StartupScope(domains)
	}
	surfaces &^= s.excludedSurface

	plan := audit.Plan{Filter: audit.Filter{
		Domains:      domains,
		Surfaces:     &surfaces,
		Paths:        paths,
		ExcludePaths: s.exclude,
		PIDs:         s.pids,
		ExcludePIDs:  s.excludePIDs,
		Units:        s.units,
		ExcludeUnits: s.excludeUnit,
	}}
	if domains&audit.DomainFiles != 0 && len(paths) > 0 {
		plan.InventoryRoots = paths
	}
	return plan
}
