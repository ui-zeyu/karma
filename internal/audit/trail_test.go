package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadTrailKeepsOneBasedLineNumbers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".bash_history")
	if err := os.WriteFile(path, []byte("first\n\nthird\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, truncated, err := readTrail(path)
	if err != nil {
		t.Fatal(err)
	}
	if truncated || len(lines) != 2 {
		t.Fatalf("lines = %+v truncated = %v", lines, truncated)
	}
	if lines[0].Line != 1 || lines[0].Text != "first" ||
		lines[1].Line != 3 || lines[1].Text != "third" {
		t.Errorf("trail lines = %+v, want lines 1 and 3", lines)
	}
}

func TestReadTrailStripsTerminalControls(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".bash_history")
	if err := os.WriteFile(path, []byte("\x1b[31mred\x1b[0m\tcmd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, _, err := readTrail(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 {
		t.Fatalf("lines = %+v", lines)
	}
	if strings.ContainsAny(lines[0].Text, "\x1b\t") {
		t.Errorf("trail text carries a terminal control: %q", lines[0].Text)
	}
}

func TestTrailEvidenceCitesTheLineThatNamesTheObject(t *testing.T) {
	path := "/etc/ld.so.preload"
	report := &Report{Findings: []Finding{{
		Class: "activation-introduction", Severity: Critical, Path: path,
	}}}
	snapshot := &Snapshot{Trail: []TrailFile{{
		Path: "/root/.bash_history",
		Lines: []Quote{
			{Path: "/root/.bash_history", Line: 7, Text: "printf '/lib/x.so\\n' > " + path},
			{Path: "/root/.bash_history", Line: 8, Text: "cat /etc/passwd"},
		},
	}}}
	attachTrailEvidence(snapshot.Trail, report)
	if len(report.Findings[0].Quotes) != 1 {
		t.Fatalf("quotes = %+v, want one history line", report.Findings[0].Quotes)
	}
	quote := report.Findings[0].Quotes[0]
	if quote.Path != "/root/.bash_history" || quote.Line != 7 {
		t.Errorf("quote = %+v, want the history line at 7", quote)
	}
}

func TestTrailEvidenceMatchesWholePathsOnly(t *testing.T) {
	path := "/etc/passwd"
	report := &Report{Findings: []Finding{{
		Class: "identity-factor", Severity: High, Path: path,
	}}}
	snapshot := &Snapshot{Trail: []TrailFile{{
		Path: "/root/.viminfo",
		Lines: []Quote{
			{Path: "/root/.viminfo", Line: 4, Text: "'0 1 0 /etc/passwd-old"},
			{Path: "/root/.viminfo", Line: 5, Text: "'0 1 0 /etc/passwd"},
		},
	}}}
	attachTrailEvidence(snapshot.Trail, report)
	if len(report.Findings[0].Quotes) != 1 {
		t.Fatalf("quotes = %+v, want only the exact path", report.Findings[0].Quotes)
	}
	if report.Findings[0].Quotes[0].Line != 5 {
		t.Errorf("quote = %+v, want line 5", report.Findings[0].Quotes[0])
	}
}

func TestTrailRowsShowTheInventory(t *testing.T) {
	file := TrailFile{
		Path: "/root/.bash_history", Owner: 0,
		Lines: []Quote{
			{Path: "/root/.bash_history", Line: 1, Text: "uname -a"},
			{Path: "/root/.bash_history", Line: 2, Text: "id"},
		},
		Facts: pathFacts("/root/.bash_history", 1200, 0o600, 0),
	}
	snapshot := &Snapshot{Boundary: boundary(), Trail: []TrailFile{file}}
	view := NewView(snapshot, Filter{})
	rows := trailRows(view, RenderOptions{Width: 100})
	if len(rows) != 2 {
		t.Fatalf("rows = %+v, want header and one file", rows)
	}
	if !strings.Contains(rows[1], "/root/.bash_history") || !strings.Contains(rows[1], "runtime") {
		t.Errorf("trail row = %q", rows[1])
	}
}

func TestTrailScopeFollowsPathAndDomain(t *testing.T) {
	files := []TrailFile{
		{Path: "/root/.bash_history", Owner: 0},
		{Path: "/home/ops/.bash_history", Owner: 1001},
	}
	if got := scopeTrail(files, nil, Filter{Paths: []string{"/root"}}); len(got) != 1 || got[0].Owner != 0 {
		t.Errorf("path scope = %+v", got)
	}
	if got := scopeTrail(files, nil, Filter{Domains: DomainPersistence}); got != nil {
		t.Errorf("service surface leaked trail rows: %+v", got)
	}
	if got := scopeTrail(files, nil, Filter{Domains: DomainTrail}); len(got) != 2 {
		t.Errorf("files surface dropped trail rows: %+v", got)
	}
}

func TestTrailPathsNameTheRootHistoryAndAuthLog(t *testing.T) {
	paths := trailPaths()
	for _, want := range []string{"/root/.bash_history", "/root/.viminfo", "/var/log/auth.log"} {
		found := false
		for _, path := range paths {
			if path == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("trail paths miss %s: %v", want, paths)
		}
	}
}

func TestShowTrailJSONCarriesTheLines(t *testing.T) {
	snapshot := &Snapshot{
		Boundary: boundary(),
		Trail: []TrailFile{{
			Path: "/root/.bash_history", Owner: 0,
			Lines: []Quote{{Path: "/root/.bash_history", Line: 2, Text: "id"}},
			Facts: pathFacts("/root/.bash_history", 1200, 0o600, 0),
		}},
	}
	section, ok := SectionFor("trail")
	if !ok {
		t.Fatal("trail section missing")
	}
	var out bytes.Buffer
	if err := WriteShowJSON(&out, NewView(snapshot, Filter{}), section, "trail", RenderOptions{}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Trail []TrailFile `json:"trail"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Trail) != 1 || len(doc.Trail[0].Lines) != 1 || doc.Trail[0].Lines[0].Text != "id" {
		t.Errorf("trail JSON = %+v", doc.Trail)
	}
}

func TestTrailPathsFollowAnAccountsHome(t *testing.T) {
	home := t.TempDir()
	snapshot := &Snapshot{Identity: IdentityState{Accounts: []Account{
		{Name: "svc", Home: home},
		{Name: "root", Home: "/root"},
	}}}
	paths := trailPathsFor(snapshot)
	want := filepath.Join(home, ".bash_history")
	for _, path := range paths {
		if path == want {
			return
		}
	}
	t.Errorf("trail paths miss %s: %v", want, paths)
}

func TestTrailPathsSkipHomesThatAreNotDirectories(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-home")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot := &Snapshot{Identity: IdentityState{Accounts: []Account{
		{Name: "sshd", Home: "/dev/null"},
		{Name: "file", Home: file},
	}}}
	for _, path := range trailPathsFor(snapshot) {
		if strings.HasPrefix(path, "/dev/null/") || strings.HasPrefix(path, file+"/") {
			t.Errorf("trail path from a non-directory home: %s", path)
		}
	}
}

func TestTrailSectionIsOneTableEntry(t *testing.T) {
	section, ok := SectionFor("trail")
	if !ok || section.Panel != "TRAIL" || section.JSONKey != "trail" {
		t.Fatalf("trail section = %+v (found %v)", section, ok)
	}
	if section.AllSurfaces {
		t.Errorf("trail section reads startup surfaces it does not use: %+v", section)
	}
	if section.Domains&DomainIdentity == 0 {
		t.Errorf("trail section does not collect account homes: %+v", section)
	}
}
