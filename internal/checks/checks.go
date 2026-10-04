// Package checks is the check catalog: it assembles each aspect's checks per
// platform.
package checks

import (
	"slices"

	"karma/internal/checks/linux"
	"karma/internal/checks/windows"
	"karma/internal/model"
)

func init() {
	// Catalog invariants: check ids are globally unique and probe labels are
	// unique within a fallback chain. The fallback note joins `skipped → current`,
	// and a repeated label in the chain would present two indistinguishable tiers.
	for _, catalog := range [][]*model.Check{linux.All, windows.All} {
		validate(catalog)
	}
}

func validate(catalog []*model.Check) {
	seen := map[string]bool{}
	for _, check := range catalog {
		if seen[check.ID] {
			panic("duplicate check id: " + check.ID)
		}
		seen[check.ID] = true
		labels := map[string]bool{}
		for _, probe := range check.Probes {
			if labels[probe.Label] {
				panic("check " + check.ID + " has a duplicate probe label: " + probe.Label)
			}
			labels[probe.Label] = true
			// head is the shape this tier wants (stopping once it has enough rows
			// counts as success), and line_limit caps an open scan and marks
			// "truncated"; with both set the truncation semantics are unclear, so
			// construction stops here
			if probe.Head > 0 && probe.LineLimit > 0 {
				panic("check " + check.ID + " probe " + probe.Label + ": Head and LineLimit are mutually exclusive")
			}
		}
	}
}

// ChecksFor returns one platform's check catalog. A new platform registers its
// catalog here.
func ChecksFor(platform model.Platform) []*model.Check {
	switch platform {
	case model.Windows:
		return windows.All
	default:
		return linux.All
	}
}

// AllChecks is the union of both platforms' catalogs: karma list shows all of
// them by default, told apart by the platform column.
func AllChecks() []*model.Check {
	return slices.Concat(linux.All, windows.All)
}
