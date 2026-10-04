// Package checks is the check catalog: it assembles each aspect's checks per
// platform.
package checks

import (
	"karma/internal/checks/linux"
	"karma/internal/checks/windows"
	"karma/internal/model"
)

// platformCatalog is one registered platform catalog.
type platformCatalog struct {
	platform model.Platform
	checks   []*model.Check
}

// catalogs is the single registry of platform catalogs: ChecksFor resolves a
// platform through it and AllChecks concatenates it in declaration order, so a
// platform is registered once. The catalog's own invariants (unique check ids,
// unique probe labels within a chain, Head and LineLimit mutually exclusive,
// unique rule and filter ids within a check) are locked by the tests; nothing
// validates at run time.
var catalogs = []platformCatalog{
	{model.Linux, linux.All},
	{model.Windows, windows.All},
}

// ChecksFor returns one platform's check catalog. Running another platform's
// checks against a target would produce misleading evidence, so a platform with
// no registered catalog stops here.
func ChecksFor(platform model.Platform) []*model.Check {
	for _, catalog := range catalogs {
		if catalog.platform == platform {
			return catalog.checks
		}
	}
	panic("no check catalog registered for platform " + string(platform))
}

// AllChecks is the union of every platform's catalog in registry order: karma
// list shows all of them by default, grouped under one banner per platform and
// aspect.
func AllChecks() []*model.Check {
	var all []*model.Check
	for _, catalog := range catalogs {
		all = append(all, catalog.checks...)
	}
	return all
}
