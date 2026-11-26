package cli

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"karma/internal/audit"
	"karma/internal/startup"
)

// scope is the positional narrowing: domains, activation surfaces, paths,
// pids and unit names.
type scope struct {
	domains         audit.Domain
	excludedDomains audit.Domain
	surfaces        map[string]bool // nil means every surface
	paths           []string
	exclude         []string
	pids            map[int]bool
	units           map[string]bool
}

// surfaceWords are the startup surfaces plus the two runtime views the
// audit's own collectors read. The startup names come from the collector
// table, so the CLI vocabulary cannot drift from what is collected.
var surfaceWords = append(startup.SurfaceWords(), "activity", "authority")

var surfaceGroups = map[string][]string{
	"persistence": startup.SurfaceWords(),
	"boot":        {"systemd", "init", "loader", "udev", "apt", "module", "system"},
	"login":       {"profile", "ssh", "pam", "xdg"},
	"schedule":    {"cron"},
	"service":     {"systemd", "supervisor"},
	"device":      {"udev"},
	"activity":    {"activity"},
}

// groupWords lists the surface groups, sorted, so the vocabulary has one
// canonical order.
func groupWords() []string {
	words := make([]string, 0, len(surfaceGroups))
	for word := range surfaceGroups {
		words = append(words, word)
	}
	sort.Strings(words)
	return words
}

// domainWords is derived from the audit registry, so the CLI vocabulary and
// the collection/judgment table cannot drift.
func domainWords() map[string]audit.Domain {
	words := map[string]audit.Domain{}
	for _, word := range audit.DomainWords() {
		if module, ok := audit.ModuleForWord(word); ok {
			words[word] = module.Bit
		}
	}
	return words
}

func parseScope(words []string) (scope, error) {
	parsed := scope{}
	for _, word := range words {
		excluded := strings.HasPrefix(word, "!")
		name := strings.TrimPrefix(word, "!")
		if name == "" {
			return scope{}, fmt.Errorf("an exclusion needs a word after \"!\"")
		}
		if domain, ok := domainWords()[name]; ok {
			if excluded {
				parsed.excludedDomains |= domain
			} else {
				parsed.domains |= domain
			}
			// A domain word keeps every activation surface in judgment scope;
			// only the domains whose rows are surface-specific name one.
			switch name {
			case "services":
				parsed.selectSurfaces(excluded)
				parsed.surfaces["systemd"] = !excluded
			case "processes", "network":
				parsed.selectSurfaces(excluded)
				parsed.surfaces["activity"] = !excluded
			case "files":
				parsed.selectSurfaces(excluded)
				parsed.surfaces["files"] = !excluded
			}
			continue
		}
		if strings.HasPrefix(name, "/proc/") {
			pid, err := strconv.Atoi(strings.TrimPrefix(name, "/proc/"))
			if err != nil {
				return scope{}, fmt.Errorf("unknown process %q", name)
			}
			if parsed.pids == nil {
				parsed.pids = map[int]bool{}
			}
			parsed.pids[pid] = !excluded
			continue
		}
		if strings.HasPrefix(name, "/") || strings.HasPrefix(name, "./") || strings.HasPrefix(name, "~/") {
			if excluded {
				parsed.exclude = append(parsed.exclude, name)
			} else {
				parsed.paths = append(parsed.paths, name)
			}
			continue
		}
		if hasUnitSuffix(name) {
			if parsed.units == nil {
				parsed.units = map[string]bool{}
			}
			parsed.units[name] = !excluded
			if excluded {
				parsed.excludedDomains |= audit.DomainServices
			} else {
				parsed.domains |= audit.DomainServices
			}
			// A unit word names a relation, so it stays out of the surface
			// selection: the services domain's own startup scope collects the
			// unit's systemd rows, and the panels the unit can answer narrow
			// by the unit itself.
			continue
		}
		names, group := surfaceGroups[name]
		if !group {
			if !contains(surfaceWords, name) {
				return scope{}, fmt.Errorf("unknown scope %q (surfaces: %s)", name, strings.Join(surfaceWords, ", "))
			}
			names = []string{name}
		}
		parsed.selectSurfaces(excluded)
		for _, surface := range names {
			parsed.surfaces[surface] = !excluded
		}
		if excluded {
			continue
		}
		if group {
			switch name {
			case "activity":
				parsed.domains |= audit.DomainProcesses | audit.DomainNetwork
			case "service":
				parsed.domains |= audit.DomainServices
			default:
				parsed.domains |= audit.DomainPersistence
			}
			continue
		}
		switch name {
		case "systemd":
			parsed.domains |= audit.DomainServices
		case "activity":
			parsed.domains |= audit.DomainProcesses | audit.DomainNetwork
		case "authority":
			parsed.domains |= audit.DomainAuthority
		default:
			parsed.domains |= audit.DomainPersistence
		}
	}
	return parsed, nil
}

// selectSurfaces allocates the surface map. An exclusion-first selection
// starts from every surface, so "!profile" keeps the rest rather than turning
// the whole host off.
func (s *scope) selectSurfaces(excluded bool) {
	if s.surfaces != nil {
		return
	}
	s.surfaces = map[string]bool{}
	if excluded {
		for _, surface := range surfaceWords {
			s.surfaces[surface] = true
		}
	}
}

func (s scope) filter(min audit.Severity) audit.Filter {
	// plan() is pure, so the off-domain list answers the same bits the
	// collectors read.
	return audit.Filter{
		Surfaces:     s.surfaces,
		Paths:        s.paths,
		ExcludePaths: s.exclude,
		PIDs:         s.pids,
		Units:        s.units,
		MinSeverity:  min,
		OffDomains:   offDomains(s.plan().Domains),
	}
}

// offDomains names the bounded domains the plan does not judge, in registry
// order. A scoped report's quiet is only about the domains it ran, so the
// masthead says which ones stayed off.
func offDomains(domains audit.Domain) []string {
	bits := domainWords()
	var off []string
	for _, word := range audit.DomainWords() {
		if bit := bits[word]; bit != 0 && bit != audit.DomainBase && domains&bit == 0 {
			off = append(off, word)
		}
	}
	return off
}

// plan turns the parsed selection into what the collectors read. No scope
// words at all means the full bounded host; a domain word means that domain;
// paths and pids alone keep the full domain set and narrow the judgment.
func (s scope) plan() audit.Plan {
	domains := s.domains
	if domains == 0 {
		if s.surfaces == nil && len(s.pids) > 0 && len(s.paths) == 0 {
			// A process scope reads the process table and its sockets; the
			// authority walk and the static inventory cannot be about one pid.
			domains = audit.DomainBase | audit.DomainProcesses | audit.DomainNetwork
		} else {
			domains = audit.AllDomains
		}
	}
	domains |= audit.DomainBase
	domains &^= s.excludedDomains
	plan := audit.Plan{
		Domains:  domains,
		Surfaces: s.surfaces,
		Paths:    s.paths,
		Exclude:  s.exclude,
		PIDs:     s.pids,
		Units:    s.units,
	}
	if domains&audit.DomainFiles != 0 && len(s.paths) > 0 {
		plan.InventoryRoots = s.paths
	}
	return plan
}

func hasUnitSuffix(name string) bool {
	switch {
	case strings.HasSuffix(name, ".service"), strings.HasSuffix(name, ".socket"),
		strings.HasSuffix(name, ".timer"), strings.HasSuffix(name, ".path"):
		return true
	}
	return false
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
