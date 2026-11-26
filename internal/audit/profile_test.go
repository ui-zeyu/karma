package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"karma/internal/startup"
	"karma/internal/trust"
)

func TestUnitFromCgroup(t *testing.T) {
	cases := map[string]string{
		"0::/system.slice/ssh.service":                   "ssh.service",
		"12:cpu,cpuacct:/system.slice/x.service":         "x.service",
		"0::/user.slice/user-1000.slice/session-2.scope": "session-2.scope",
		"0::/": "",
	}
	for text, want := range cases {
		if got := unitFromCgroup(text); got != want {
			t.Errorf("unitFromCgroup(%q) = %q, want %q", text, got, want)
		}
	}
}

func TestExtractPaths(t *testing.T) {
	body := []byte("exec /opt/app/agent --config=/etc/app/agent.yml\n" +
		"see https://example.test/api/push and /usr/lib/libfoo.so\n")
	got := extractPaths(body)
	want := map[string]bool{"/opt/app/agent": true, "/etc/app/agent.yml": true, "/usr/lib/libfoo.so": true}
	for _, path := range got {
		delete(want, path)
	}
	if len(want) != 0 {
		t.Errorf("extractPaths missed %v (got %v)", want, got)
	}
	for _, path := range got {
		if path == "/api/push" {
			t.Errorf("a URL path was read as a file: %v", got)
		}
	}
}

func TestManifestClassPath(t *testing.T) {
	body := "Manifest-Version: 1.0\r\nClass-Path: lib/a.jar\r\n lib/b.jar\r\nMain-Class: x\r\n"
	got := manifestClassPath(body)
	if len(got) != 2 || got[0] != "lib/a.jar" || got[1] != "lib/b.jar" {
		t.Errorf("classpath = %v", got)
	}
}

func TestBuildProfileUnitMissingTarget(t *testing.T) {
	unitPath := "/etc/systemd/system/x.service"
	target := "/usr/local/libexec/x"
	unitFacts := trust.Build(unitPath, trust.Attrs{
		Kind: trust.File, Mode: 0o644, UID: 0, Real: unitPath, CTime: 900,
		Package: "systemd", PackageKnown: true,
	})
	targetFacts := trust.Build(target, trust.Attrs{Kind: trust.Missing, UID: -1, GID: -1, Real: target})
	snapshot := &Snapshot{
		Boundary:     Boundary{Time: time.Unix(1000, 0), Kind: "container", Source: "pid1", Confidence: HighConfidence},
		PackageTimes: map[string]time.Time{"systemd": time.Unix(500, 0)},
		Objects:      map[string]trust.Facts{unitPath: unitFacts, target: targetFacts},
		Activations: []startup.Edge{{
			Surface: startup.SurfaceSystemd, Trigger: unitPath, Target: target,
			Mechanism: "ExecStart", Kind: startup.Exec,
			TriggerFacts: unitFacts, TargetFacts: targetFacts,
		}},
	}
	profile, err := BuildProfile(context.Background(), snapshot, "unit:x.service", Info)
	if err != nil {
		t.Fatal(err)
	}
	missing := profileNode(profile, "file:"+target)
	if missing == nil || !missing.Missing {
		t.Fatalf("missing target node = %+v", missing)
	}
	found := false
	for _, finding := range profile.Findings {
		if finding.Class == "unit-target-missing" && finding.Path == target {
			found = true
		}
	}
	if !found {
		t.Errorf("profile findings = %+v, want unit-target-missing", profile.Findings)
	}
}

func TestBuildProfileFollowsShellReference(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.conf")
	if err := os.WriteFile(target, []byte("key=value\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "source.sh")
	if err := os.WriteFile(source, []byte("#!/bin/sh\nsource "+target+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	snapshot := &Snapshot{
		Boundary: Boundary{Time: time.Unix(1, 0), Kind: "container", Source: "pid1", Confidence: HighConfidence},
		Objects:  map[string]trust.Facts{},
	}
	profile, err := BuildProfile(context.Background(), snapshot, source, Info)
	if err != nil {
		t.Fatal(err)
	}
	if node := profileNode(profile, "file:"+target); node == nil {
		t.Fatalf("target node missing; nodes = %+v", profile.Nodes)
	}
	linked := false
	for _, edge := range profile.Edges {
		if edge.From == "file:"+source && edge.To == "file:"+target &&
			(edge.Source == "shell" || edge.Source == "lexical") {
			linked = true
		}
	}
	if !linked {
		t.Errorf("edges = %+v, want a shell or lexical edge to the target", profile.Edges)
	}
}
