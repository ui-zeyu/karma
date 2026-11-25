package audit

import (
	"os"
	"strings"
	"testing"
	"time"

	"karma/internal/startup"
	"karma/internal/trust"
)

func pathFacts(path string, ctime int64, mode uint32, owner int) trust.Facts {
	return trust.Build(path, trust.Attrs{
		Kind: trust.File, Mode: os.FileMode(mode), UID: owner, GID: owner,
		Real: path, CTime: ctime,
	})
}

func boundary() Boundary {
	return Boundary{Time: time.Unix(1000, 0), Kind: "container", Source: "pid1", Confidence: HighConfidence}
}

func TestOriginOfTheArtifactAndItsDelta(t *testing.T) {
	base := boundary()
	pkg := map[string]time.Time{"coreutils": time.Unix(1200, 0)}
	cases := []struct {
		name  string
		facts trust.Facts
		want  Origin
	}{
		{"package before the boundary", trust.Build("/usr/bin/true", trust.Attrs{
			Kind: trust.File, Mode: 0o755, UID: 0, Real: "/usr/bin/true",
			CTime: 900, Package: "openssh", PackageKnown: true,
		}), Base},
		{"package installed after the boundary", trust.Build("/usr/bin/new", trust.Attrs{
			Kind: trust.File, Mode: 0o755, UID: 0, Real: "/usr/bin/new",
			CTime: 1200, Package: "coreutils", PackageKnown: true,
		}), Provisioned},
		{"package file changed after the boundary", trust.Build("/usr/bin/edited", trust.Attrs{
			Kind: trust.File, Mode: 0o755, UID: 0, Real: "/usr/bin/edited",
			CTime: 1200, Package: "other", PackageKnown: true,
		}), Modified},
		{"unowned file after the boundary", pathFacts("/var/lib/.loader", 1200, 0o755, 0), Runtime},
		{"unowned file before the boundary", pathFacts("/opt/tool", 900, 0o755, 0), PreExisting},
	}
	for _, test := range cases {
		got, _ := originOf(test.facts, base, pkg)
		if got != test.want {
			t.Errorf("%s: origin = %s, want %s", test.name, got, test.want)
		}
	}
}

func TestJudgeRuntimeObjectInAnActivationSurface(t *testing.T) {
	trigger := pathFacts("/etc/profile.d/vendor.sh", 1200, 0o644, 0)
	target := pathFacts("/var/lib/vendor/.loader.sh", 1200, 0o755, 0)
	snapshot := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{trigger.Path: trigger, target.Path: target},
		Activations: []startup.Edge{{
			Surface: startup.SurfaceProfile, Reach: startup.Login, AS: "root",
			Trigger: trigger.Path, Target: target.Path, Kind: startup.Exec,
			TriggerFacts: trigger, TargetFacts: target,
		}},
	}
	report := Judge(snapshot, Filter{})
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %+v, want one", report.Findings)
	}
	finding := report.Findings[0]
	if finding.Class != "tcb-introduction" || finding.Path != trigger.Path {
		t.Errorf("finding = %+v", finding)
	}
	if finding.Severity != Critical || finding.Reach != RootAsset {
		t.Errorf("severity = %s reach = %s, want critical root", finding.Severity, finding.Reach)
	}
}

func TestJudgeArtifactActivationIsQuiet(t *testing.T) {
	trigger := pathFacts("/etc/systemd/system/sshd.service", 900, 0o644, 0)
	target := trust.Build("/usr/sbin/sshd", trust.Attrs{
		Kind: trust.File, Mode: 0o755, UID: 0, Real: "/usr/sbin/sshd",
		CTime: 900, Package: "openssh-server", PackageKnown: true,
	})
	snapshot := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{trigger.Path: trigger, target.Path: target},
		Activations: []startup.Edge{{
			Surface: startup.SurfaceSystemd, Reach: startup.BootEnabled, AS: "root",
			Trigger: trigger.Path, Target: target.Path, Kind: startup.Exec,
			TriggerFacts: trigger, TargetFacts: target,
		}},
	}
	if report := Judge(snapshot, Filter{}); len(report.Findings) != 0 {
		t.Errorf("findings = %+v, want none", report.Findings)
	}
}

func TestJudgeWritableActivationSurface(t *testing.T) {
	trigger := pathFacts("/etc/profile.d/open.sh", 900, 0o666, 0)
	target := trust.Build("/usr/bin/true", trust.Attrs{
		Kind: trust.File, Mode: 0o755, UID: 0, Real: "/usr/bin/true",
		CTime: 900, Package: "coreutils", PackageKnown: true,
	})
	snapshot := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{trigger.Path: trigger, target.Path: target},
		Activations: []startup.Edge{{
			Surface: startup.SurfaceProfile, Reach: startup.Login, AS: "root",
			Trigger: trigger.Path, Target: target.Path, Kind: startup.Source,
			TriggerFacts: trigger, TargetFacts: target,
		}},
	}
	report := Judge(snapshot, Filter{})
	if len(report.Findings) != 1 || report.Findings[0].Class != "tcb-writable" {
		t.Fatalf("findings = %+v, want one writable finding", report.Findings)
	}
	if report.Findings[0].Severity != High {
		t.Errorf("severity = %s, want high", report.Findings[0].Severity)
	}
}

func TestJudgeRuntimeProcessAndAuthorityObject(t *testing.T) {
	image := pathFacts("/tmp/dropper", 1200, 0o755, 0)
	shadow := pathFacts("/etc/shadow", 1200, 0o640, 0)
	snapshot := &Snapshot{
		Boundary:  boundary(),
		Objects:   map[string]trust.Facts{image.Path: image, shadow.Path: shadow},
		Authority: []string{shadow.Path},
		Processes: []Process{{
			PID: 42, UID: 0, Exe: image.Path, Cmdline: "/tmp/dropper", ExeFacts: image,
		}},
	}
	report := Judge(snapshot, Filter{})
	classes := map[string]bool{}
	for _, finding := range report.Findings {
		classes[finding.Class] = true
	}
	if !classes["runtime-process"] || !classes["authority-object"] {
		t.Fatalf("findings = %+v", report.Findings)
	}
}

func TestJudgeUnownedTargetWithoutAnOriginDelta(t *testing.T) {
	trigger := pathFacts("/etc/systemd/system/local.service", 900, 0o644, 0)
	target := trust.Build("/usr/local/libexec/agent", trust.Attrs{
		Kind: trust.File, Mode: 0o755, UID: 0, Real: "/usr/local/libexec/agent",
		CTime: 900, PackageKnown: true,
	})
	snapshot := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{trigger.Path: trigger, target.Path: target},
		Activations: []startup.Edge{{
			Surface: startup.SurfaceSystemd, Reach: startup.BootEnabled, AS: "root",
			Trigger: trigger.Path, Target: target.Path, Kind: startup.Exec,
			TriggerFacts: trigger, TargetFacts: target,
		}},
	}
	report := Judge(snapshot, Filter{})
	if len(report.Findings) != 1 || report.Findings[0].Class != "unowned-target" {
		t.Fatalf("findings = %+v, want one unowned target", report.Findings)
	}
	if report.Findings[0].Severity != High {
		t.Errorf("severity = %s, want high", report.Findings[0].Severity)
	}
}

func TestJudgeUnownedRootProcessWithoutAnOriginDelta(t *testing.T) {
	image := trust.Build("/bin/bash", trust.Attrs{
		Kind: trust.File, Mode: 0o755, UID: 0, Real: "/bin/bash",
		CTime: 900, Package: "bash", PackageKnown: true,
	})
	script := trust.Build("/usr/local/bin/agent", trust.Attrs{
		Kind: trust.File, Mode: 0o755, UID: 0, Real: "/usr/local/bin/agent",
		CTime: 900, PackageKnown: true,
	})
	snapshot := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{image.Path: image, script.Path: script},
		Processes: []Process{{
			PID: 77, UID: 0, Exe: image.Path, Script: script.Path,
			Cmdline:  "/bin/bash /usr/local/bin/agent",
			ExeFacts: image, ScriptFacts: script,
		}},
	}
	report := Judge(snapshot, Filter{})
	if len(report.Findings) != 1 || report.Findings[0].Class != "unowned-process" {
		t.Fatalf("findings = %+v, want one unowned process", report.Findings)
	}
	if report.Findings[0].Path != script.Path || report.Findings[0].Severity != High {
		t.Errorf("finding = %+v", report.Findings[0])
	}
}

func TestPIDScopeJudgesOnlyThatProcess(t *testing.T) {
	trigger := pathFacts("/etc/profile.d/x.sh", 1200, 0o644, 0)
	target := pathFacts("/opt/x.sh", 1200, 0o755, 0)
	image := pathFacts("/tmp/x", 1200, 0o755, 0)
	snapshot := &Snapshot{
		Boundary: boundary(),
		Objects: map[string]trust.Facts{
			trigger.Path: trigger, target.Path: target, image.Path: image,
		},
		Activations: []startup.Edge{{
			Surface: startup.SurfaceProfile, Reach: startup.Login, AS: "root",
			Trigger: trigger.Path, Target: target.Path,
			TriggerFacts: trigger, TargetFacts: target,
		}},
		Processes: []Process{{PID: 42, UID: 0, Exe: image.Path, ExeFacts: image}},
	}
	report := Judge(snapshot, Filter{PIDs: map[int]bool{42: true}})
	if len(report.Findings) != 1 || report.Findings[0].Class != "runtime-process" {
		t.Fatalf("findings = %+v, want only the process", report.Findings)
	}
}

func TestScopeNarrowsSurfacesAndPaths(t *testing.T) {
	trigger := pathFacts("/etc/profile.d/x.sh", 1200, 0o644, 0)
	target := pathFacts("/opt/x.sh", 1200, 0o755, 0)
	snapshot := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{trigger.Path: trigger, target.Path: target},
		Activations: []startup.Edge{{
			Surface: startup.SurfaceProfile, Reach: startup.Login, AS: "root",
			Trigger: trigger.Path, Target: target.Path,
			TriggerFacts: trigger, TargetFacts: target,
		}},
	}
	if report := Judge(snapshot, Filter{Surfaces: map[string]bool{"systemd": true}}); len(report.Findings) != 0 {
		t.Errorf("a systemd scope judged a profile edge: %+v", report.Findings)
	}
	if report := Judge(snapshot, Filter{Paths: []string{"/opt"}}); len(report.Findings) != 1 {
		t.Errorf("a path scope missed the target: %+v", report.Findings)
	}
	if report := Judge(snapshot, Filter{Paths: []string{"/var/www"}}); len(report.Findings) != 0 {
		t.Errorf("a non-matching path scope judged the edge: %+v", report.Findings)
	}
}

func TestRenderKeepsThePanelLanguageAndTheRawInventory(t *testing.T) {
	trigger := pathFacts("/etc/systemd/system/x.service", 1200, 0o644, 0)
	target := pathFacts("/opt/x", 1200, 0o755, 0)
	snapshot := &Snapshot{
		Boundary: boundary(),
		Host:     Host{Hostname: "lab", OS: "Ubuntu", Kernel: "5.15", UID: 0},
		Source:   "native",
		Objects:  map[string]trust.Facts{trigger.Path: trigger, target.Path: target},
		Activations: []startup.Edge{{
			Surface: startup.SurfaceSystemd, Reach: startup.BootEnabled, AS: "root",
			Trigger: trigger.Path, Target: target.Path, Kind: startup.Exec, Mechanism: "ExecStart",
			TriggerFacts: trigger, TargetFacts: target,
		}},
		Services: []Service{{Unit: "x.service", Load: "loaded", Active: "active", Sub: "running", Description: "X"}},
		Sockets:  []Socket{{Proto: "tcp", State: "LISTEN", Local: "0.0.0.0:22", Peer: "0.0.0.0:*", PID: 1, Comm: "sshd"}},
	}
	report := Judge(snapshot, Filter{})
	var out strings.Builder
	Render(&out, report, snapshot, RenderOptions{
		Version: "9.9.9", Width: 100, Evidence: true,
	})
	text := out.String()
	for _, want := range []string{"KARMA", "9.9.9", "CRITICAL", "EVIDENCE", "ACTIVATION", "SERVICE", "LISTEN", "x.service", "0.0.0.0:22"} {
		if !strings.Contains(text, want) {
			t.Errorf("report does not contain %q:\n%s", want, text)
		}
	}
}
