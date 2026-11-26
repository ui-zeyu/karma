package cli

import (
	"testing"

	"karma/internal/audit"
)

func TestScopePlanDomains(t *testing.T) {
	cases := []struct {
		name     string
		words    []string
		domains  audit.Domain
		surfaces map[string]bool
		units    map[string]bool
	}{
		{name: "bare", domains: audit.AllDomains},
		{name: "services", words: []string{"services"},
			domains:  audit.DomainBase | audit.DomainServices,
			surfaces: map[string]bool{"systemd": true}},
		{name: "files", words: []string{"files"},
			domains:  audit.DomainBase | audit.DomainFiles,
			surfaces: map[string]bool{"files": true}},
		{name: "processes", words: []string{"processes"},
			domains:  audit.DomainBase | audit.DomainProcesses,
			surfaces: map[string]bool{"activity": true}},
		{name: "persistence", words: []string{"persistence"},
			domains: audit.DomainBase | audit.DomainPersistence},
		{name: "kernel", words: []string{"kernel"},
			domains: audit.DomainBase | audit.DomainKernel},
		{name: "packages", words: []string{"packages"},
			domains: audit.DomainBase | audit.DomainPackages},
		{name: "web", words: []string{"web"},
			domains: audit.DomainBase | audit.DomainWeb},
		{name: "identity", words: []string{"identity"},
			domains: audit.DomainBase | audit.DomainIdentity},
		{name: "unit", words: []string{"sshd.service"},
			domains:  audit.DomainBase | audit.DomainServices,
			surfaces: map[string]bool{"systemd": true},
			units:    map[string]bool{"sshd.service": true}},
		{name: "pid", words: []string{"/proc/1"},
			domains: audit.DomainBase | audit.DomainProcesses | audit.DomainNetwork},
	}
	for _, test := range cases {
		parsed, err := parseScope(test.words)
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		plan := parsed.plan()
		if plan.Domains != test.domains {
			t.Errorf("%s: domains = %b, want %b", test.name, plan.Domains, test.domains)
		}
		if test.surfaces != nil {
			for surface, want := range test.surfaces {
				if plan.Surfaces[surface] != want {
					t.Errorf("%s: surface %s = %t, want %t", test.name, surface, plan.Surfaces[surface], want)
				}
			}
		}
		for unit := range test.units {
			if !plan.Units[unit] {
				t.Errorf("%s: unit %s missing from the plan", test.name, unit)
			}
		}
	}
}

func TestScopeCanExcludeTheKernelDomain(t *testing.T) {
	parsed, err := parseScope([]string{"!kernel"})
	if err != nil {
		t.Fatal(err)
	}
	plan := parsed.plan()
	if plan.Has(audit.DomainKernel) {
		t.Errorf("!kernel kept the kernel domain: %b", plan.Domains)
	}
	if !plan.Has(audit.DomainServices) || !plan.Has(audit.DomainFiles) {
		t.Errorf("!kernel dropped another domain: %b", plan.Domains)
	}
}

func TestGraphPlanReadsOneDomain(t *testing.T) {
	cases := map[string]audit.Domain{
		"identity":  audit.DomainBase | audit.DomainIdentity,
		"network":   audit.DomainBase | audit.DomainProcesses | audit.DomainNetwork,
		"packages":  audit.DomainBase | audit.DomainPackages,
		"boot":      audit.DomainBase | audit.DomainPersistence,
		"web":       audit.DomainBase | audit.DomainWeb,
		"kernel":    audit.DomainBase | audit.DomainKernel,
		"authority": audit.DomainBase | audit.DomainAuthority,
	}
	for word, want := range cases {
		plan, ok := audit.GraphPlan(word)
		if !ok || plan.Domains != want {
			t.Errorf("graphPlan(%q) = %+v ok=%t, want domains %b", word, plan, ok, want)
		}
	}
	if _, ok := audit.GraphPlan("unknown"); ok {
		t.Errorf("unknown graph domain was accepted")
	}
}

func TestScopeFilesUsesPathsAsInventoryRoots(t *testing.T) {
	parsed, err := parseScope([]string{"files", "/opt/vendor"})
	if err != nil {
		t.Fatal(err)
	}
	plan := parsed.plan()
	if len(plan.InventoryRoots) != 1 || plan.InventoryRoots[0] != "/opt/vendor" {
		t.Errorf("inventory roots = %v", plan.InventoryRoots)
	}
}
