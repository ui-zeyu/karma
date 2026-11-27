package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"karma/internal/audit"
)

func TestScopeResolvesTheRelativePathForms(t *testing.T) {
	parsed, err := parseScope([]string{"./var/www", "~/site"})
	if err != nil {
		t.Fatal(err)
	}
	plan := parsed.plan()
	if len(plan.Paths) != 2 {
		t.Fatalf("paths = %v", plan.Paths)
	}
	for _, path := range plan.Paths {
		if !filepath.IsAbs(path) {
			t.Errorf("relative scope reached the plan: %q", path)
		}
	}
	if !strings.HasSuffix(plan.Paths[0], "/var/www") {
		t.Errorf("dot path = %q", plan.Paths[0])
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	if plan.Paths[1] != filepath.Join(home, "site") {
		t.Errorf("home path = %q, want %q", plan.Paths[1], filepath.Join(home, "site"))
	}
}

func TestScopeAcceptsEveryUnitKind(t *testing.T) {
	for _, word := range []string{"multi-user.target", "swapfile.swap", "data.mount", "backup.timer"} {
		parsed, err := parseScope([]string{word})
		if err != nil {
			t.Errorf("%s: %v", word, err)
			continue
		}
		plan := parsed.plan()
		if !plan.Units[word] {
			t.Errorf("%s is missing from the unit set", word)
		}
		if !plan.Has(audit.DomainPersistence) || !plan.Has(audit.DomainServices) {
			t.Errorf("%s domains = %b", word, plan.Domains)
		}
	}
}

func TestGraphRejectsADomainWithoutAGraphView(t *testing.T) {
	for _, word := range []string{"persistence", "processes", "services"} {
		err := runGraph(context.Background(), nil, io.Discard, word, auditFlags{})
		if err == nil || !strings.Contains(err.Error(), "no domain view") {
			t.Errorf("graph %q = %v, want a no-domain-view error", word, err)
		}
	}
}

func TestSinceBootRetargetsTheBoundary(t *testing.T) {
	if _, err := parseSince("boot"); err != nil {
		t.Fatalf("boot is not accepted: %v", err)
	}
	if _, err := parseSince("nonsense"); err == nil {
		t.Fatal("a mistyped boundary was accepted")
	}
	boot := time.Unix(1234, 0)
	snapshot := &audit.Snapshot{Boot: boot}
	if err := applySince(snapshot, sinceSpec{kind: sinceBoot}); err != nil {
		t.Fatal(err)
	}
	if !snapshot.Boundary.Time.Equal(boot) || snapshot.Boundary.Source != "boot" {
		t.Errorf("boot boundary = %+v", snapshot.Boundary)
	}
	if err := applySince(&audit.Snapshot{}, sinceSpec{kind: sinceBoot}); err == nil {
		t.Fatal("an unreadable boot time was accepted")
	}
}

func TestSinceDurationAnchorsAtParseTime(t *testing.T) {
	before := time.Now()
	spec, err := parseSince("24h")
	if err != nil {
		t.Fatal(err)
	}
	if spec.kind != sinceOperator {
		t.Fatalf("kind = %q, want operator", spec.kind)
	}
	// The parse-time anchor is now; the boundary is a day before it.
	if spec.at.Before(before.Add(-24*time.Hour).Add(-time.Second)) ||
		spec.at.After(time.Now().Add(-24*time.Hour).Add(time.Second)) {
		t.Fatalf("a duration anchored at %v, not at parse time", spec.at)
	}
	stamp := time.Date(2026, 3, 1, 8, 0, 0, 0, time.UTC)
	spec, err = parseSince(stamp.Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	if spec.kind != sinceOperator || !spec.at.Equal(stamp) {
		t.Fatalf("an RFC3339 stamp parsed as %+v", spec)
	}
	if _, err := parseSince("provision"); err != nil {
		t.Fatal(err)
	}
}
