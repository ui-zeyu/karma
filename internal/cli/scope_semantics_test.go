package cli

// The scope grammar's judgments: words are sets, exclusions are applied last,
// and a domain word never turns another domain's rows off.

import (
	"slices"
	"strings"
	"testing"

	"karma/internal/audit"
	"karma/internal/startup"
)

// TestDomainWordKeepsItsStartupSurfaces pins "audit persistence": the word
// names every startup surface, so every activation edge is collected and
// judged.
func TestDomainWordKeepsItsStartupSurfaces(t *testing.T) {
	parsed, err := parseScope([]string{"persistence"})
	if err != nil {
		t.Fatal(err)
	}
	plan := parsed.plan()
	if plan.Surfaces == nil || *plan.Surfaces != startup.AllScope() {
		t.Errorf("persistence surfaces = %v, want every surface", plan.Surfaces)
	}
}

func TestSurfaceExclusionIsExclusionFirst(t *testing.T) {
	parsed, err := parseScope([]string{"!profile"})
	if err != nil {
		t.Fatal(err)
	}
	surfaces := parsed.plan().Surfaces
	if surfaces == nil {
		t.Fatal("no surface set")
	}
	if surfaces.Has(startup.SurfaceProfile) {
		t.Error("the excluded surface stayed on")
	}
	for _, surface := range startup.SurfaceWords() {
		if surface == "profile" {
			continue
		}
		if !surfaces.Has(startup.Surface(surface)) {
			t.Errorf("!profile turned %s off too", surface)
		}
	}
}

func TestSurfaceGroupExpandsToSurfacesAndDomain(t *testing.T) {
	parsed, err := parseScope([]string{"boot"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.domains&audit.DomainPersistence == 0 {
		t.Errorf("the boot group carried no persistence domain: %b", parsed.domains)
	}
	for _, surface := range groups["boot"].surfaces {
		if !parsed.surfaces.Has(startup.Surface(surface)) {
			t.Errorf("the boot group did not turn on %s", surface)
		}
	}
	plan := parsed.plan()
	for _, surface := range groups["boot"].surfaces {
		if !plan.Surfaces.Has(startup.Surface(surface)) {
			t.Errorf("the boot plan's surface set misses %s", surface)
		}
	}
}

func TestScopeGrammarErrors(t *testing.T) {
	if _, err := parseScope([]string{"bogus"}); err == nil || !strings.Contains(err.Error(), "unknown scope") {
		t.Errorf("an unknown word must be refused, got %v", err)
	}
	if _, err := parseScope([]string{"!"}); err == nil || !strings.Contains(err.Error(), "exclusion") {
		t.Errorf("a bare exclusion must be refused, got %v", err)
	}
	if _, err := parseScope([]string{"/proc/not-a-pid"}); err == nil {
		t.Error("a malformed process word must be refused")
	}
}

func TestFilterCarriesTheSelection(t *testing.T) {
	parsed, err := parseScope([]string{"/var/www", "!/var/www/old", "/proc/33", "sshd.service", "persistence"})
	if err != nil {
		t.Fatal(err)
	}
	filter := parsed.plan().Filter
	if len(filter.Paths) != 1 || filter.Paths[0] != "/var/www" {
		t.Errorf("paths = %v", filter.Paths)
	}
	if len(filter.ExcludePaths) != 1 || filter.ExcludePaths[0] != "/var/www/old" {
		t.Errorf("exclusions = %v", filter.ExcludePaths)
	}
	if !filter.PIDs[33] {
		t.Errorf("pids = %v", filter.PIDs)
	}
	if !filter.Units["sshd.service"] {
		t.Errorf("units = %v", filter.Units)
	}
}

// TestUnitExclusionKeepsTheDomain pins the difference between excluding one
// unit and turning the services domain off.
func TestUnitExclusionKeepsTheDomain(t *testing.T) {
	parsed, err := parseScope([]string{"!sshd.service"})
	if err != nil {
		t.Fatal(err)
	}
	plan := parsed.plan()
	if !plan.Has(audit.DomainServices) {
		t.Errorf("!unit removed the services domain: %b", plan.Domains)
	}
	if !plan.ExcludeUnits["sshd.service"] || len(plan.Units) != 0 {
		t.Errorf("unit exclusion = %v positive = %v", plan.ExcludeUnits, plan.Units)
	}
}

// TestWordOrderDoesNotChangeTheScope pins the set semantics: includes union,
// exclusions subtract, and the order on the command line does not matter.
func TestPathScopeSelectsTheDomainsItCanExplain(t *testing.T) {
	parsed, err := parseScope([]string{"/etc/passwd"})
	if err != nil {
		t.Fatal(err)
	}
	plan := parsed.plan()
	if !plan.Has(audit.DomainIdentity) || !plan.Has(audit.DomainFiles) || !plan.Has(audit.DomainAuthority) {
		t.Errorf("path domains = %b, want identity/files/authority", plan.Domains)
	}
	if plan.Has(audit.DomainProcesses) || plan.Has(audit.DomainNetwork) || plan.Has(audit.DomainKernel) {
		t.Errorf("path domains = %b, want no process/network/kernel", plan.Domains)
	}
	parsed, err = parseScope([]string{"/etc/passwd", "/proc/1"})
	if err != nil {
		t.Fatal(err)
	}
	if plan = parsed.plan(); !plan.Has(audit.DomainProcesses) || !plan.Has(audit.DomainNetwork) {
		t.Errorf("path+pid domains = %b, want process context", plan.Domains)
	}
	parsed, err = parseScope([]string{"/etc"})
	if err != nil {
		t.Fatal(err)
	}
	plan = parsed.plan()
	if !plan.Has(audit.DomainIdentity) || !plan.Has(audit.DomainServices) || !plan.Has(audit.DomainKernel) {
		t.Errorf("/etc domains = %b, want identity/services/kernel", plan.Domains)
	}
}

func TestWordOrderDoesNotChangeTheScope(t *testing.T) {
	pairs := [][2][]string{
		{{"processes", "!network"}, {"!network", "processes"}},
		{{"network", "!processes"}, {"!processes", "network"}},
		{{"cron", "!profile"}, {"!profile", "cron"}},
		{{"files", "persistence"}, {"persistence", "files"}},
	}
	for _, pair := range pairs {
		left, err := parseScope(pair[0])
		if err != nil {
			t.Fatalf("%v: %v", pair[0], err)
		}
		right, err := parseScope(pair[1])
		if err != nil {
			t.Fatalf("%v: %v", pair[1], err)
		}
		lp, rp := left.plan(), right.plan()
		if lp.Domains != rp.Domains || *lp.Surfaces != *rp.Surfaces {
			t.Errorf("%v and %v differ: %b/%b vs %b/%b", pair[0], pair[1],
				lp.Domains, *lp.Surfaces, rp.Domains, *rp.Surfaces)
		}
	}
}

// TestShowSectionHonorsSurfaceExclusions pins the inventory rule: an
// activation section reads every surface the scope left on, not the excluded
// one it was explicitly told to drop.
func TestShowSectionHonorsSurfaceExclusions(t *testing.T) {
	parsed, err := parseScope([]string{"!systemd"})
	if err != nil {
		t.Fatal(err)
	}
	section, ok := audit.SectionFor("activation")
	if !ok {
		t.Fatal("activation section missing")
	}
	plan := section.Plan(parsed.plan())
	if plan.Surfaces == nil || plan.Surfaces.Has(startup.SurfaceSystemd) {
		t.Errorf("activation section surfaces = %v, want systemd excluded", plan.Surfaces)
	}
	if !plan.Surfaces.Has(startup.SurfaceCron) {
		t.Errorf("activation section lost the other surfaces: %v", plan.Surfaces)
	}
}

// TestExcludedActivityRemovesBothDomains pins the group's exclusion effect.
func TestExcludedActivityRemovesBothDomains(t *testing.T) {
	parsed, err := parseScope([]string{"!activity"})
	if err != nil {
		t.Fatal(err)
	}
	plan := parsed.plan()
	if plan.Has(audit.DomainProcesses) || plan.Has(audit.DomainNetwork) {
		t.Errorf("!activity kept activity domains: %b", plan.Domains)
	}
	if off := plan.OffDomains(); !slices.Contains(off, "processes") || !slices.Contains(off, "network") {
		t.Errorf("off domains = %v", off)
	}
}

// TestOffDomainsListTheUnjudgedDomains pins the masthead's honesty rule: a
// scoped run names the bounded domains it did not judge, and a bare run
// leaves the list empty.
func TestOffDomainsListTheUnjudgedDomains(t *testing.T) {
	parsed, err := parseScope([]string{"persistence"})
	if err != nil {
		t.Fatal(err)
	}
	off := parsed.plan().OffDomains()
	if slices.Contains(off, "persistence") {
		t.Errorf("the judged domain is listed off: %v", off)
	}
	for _, word := range audit.DomainWords() {
		if word == "persistence" {
			continue
		}
		if !slices.Contains(off, word) {
			t.Errorf("off domains = %v, want %s listed", off, word)
		}
	}
	bare, err := parseScope(nil)
	if err != nil {
		t.Fatal(err)
	}
	if off := bare.plan().OffDomains(); len(off) != 0 {
		t.Errorf("a bare run lists off domains: %v", off)
	}
}
