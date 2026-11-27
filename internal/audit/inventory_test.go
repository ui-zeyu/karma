package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"karma/internal/trust"
)

func TestFormatSibling(t *testing.T) {
	file := UnownedFile{Dir: "/usr/bin", Total: 100, Owned: 99}
	got := formatSibling(file)
	if got == "" || got == "the directory has no package-owned peer count" {
		t.Errorf("formatSibling = %q", got)
	}
}

func TestRootScriptScanFindsTheEntrypointAndSkipsData(t *testing.T) {
	dir := t.TempDir()
	start := filepath.Join(dir, "start.sh")
	if err := os.WriteFile(start, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	owned := filepath.Join(dir, "owned.sh")
	if err := os.WriteFile(owned, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	files, total, ownedCount, err := scanRootScripts(context.Background(), dir,
		func(path string) bool { return path == owned }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != start || !files[0].Root {
		t.Fatalf("root scripts = %+v, want %s", files, start)
	}
	if total != 3 || ownedCount != 1 {
		t.Errorf("entry counts = %d/%d, want 3 entries and 1 owned", total, ownedCount)
	}
}

func TestRunningRootScriptIsLeftToTheProcessJudge(t *testing.T) {
	dir := t.TempDir()
	start := filepath.Join(dir, "start.sh")
	if err := os.WriteFile(start, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	files, _, _, err := scanRootScripts(context.Background(), dir,
		func(string) bool { return false }, map[string]bool{start: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Errorf("a running entrypoint is also reported by the static inventory: %+v", files)
	}
}

func TestDedupeUnownedPrefersTheRootEntry(t *testing.T) {
	path := "/start.sh"
	files := dedupeUnowned([]UnownedFile{
		{Path: path, Dir: "/", Mode: 0o755},
		{Path: path, Dir: "/", Root: true, Mode: 0o755},
	})
	if len(files) != 1 || !files[0].Root {
		t.Errorf("dedupe = %+v, want one root entry", files)
	}
}

func TestRootScriptFindingNamesTheRootLayer(t *testing.T) {
	path := "/start.sh"
	snapshot := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{path: pathFacts(path, 1200, 0o755, 0)},
		Unowned: []UnownedFile{{
			Path: path, Dir: "/", Root: true, RootOwned: true, Mode: 0o755,
			Total: 10, Owned: 9,
		}},
	}
	findings := unownedFindings(snapshot, snapshot.Unowned, snapshot.Assessor())
	if len(findings) != 1 {
		t.Fatalf("findings = %+v", findings)
	}
	if findings[0].Title != "root-level executable no package owns" ||
		!strings.Contains(findings[0].Detail, "entrypoint") {
		t.Errorf("root finding = %+v", findings[0])
	}
	if evidence := strings.Join(findings[0].Evidence, "\n"); !strings.Contains(evidence, "filesystem root") {
		t.Errorf("root evidence = %q", evidence)
	}
}
