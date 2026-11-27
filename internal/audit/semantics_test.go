package audit

// The judgment semantics as tables: the reach a relation answers, the severities
// it maps to, and the scope rules that decide whether an object is judged at
// all. These are the sentences the findings are written in; a change here is a
// change in what every report says.

import (
	"os"
	"strings"
	"testing"
	"time"

	"karma/internal/startup"
	"karma/internal/trust"
)

func TestSeverityLadders(t *testing.T) {
	cases := []struct {
		origin Origin
		reach  Reach
		want   Severity
	}{
		{Runtime, RootAsset, Critical},
		{Modified, RootAsset, High},
		{Unknown, RootAsset, Medium},
		{Base, RootAsset, Low},
		{Runtime, ServiceAsset, High},
		{Modified, ServiceAsset, Medium},
		{Runtime, UserAsset, Medium},
		{Modified, UserAsset, Low},
		{Runtime, KernelAsset, Critical},
		{Base, UserAsset, Info},
	}
	for _, test := range cases {
		if got := severityFor(test.origin, test.reach); got != test.want {
			t.Errorf("severityFor(%s, %s) = %s, want %s", test.origin, test.reach, got, test.want)
		}
	}
	writable := []struct {
		reach Reach
		want  Severity
	}{{RootAsset, High}, {ServiceAsset, Medium}, {UserAsset, Low}, {KernelAsset, High}}
	for _, test := range writable {
		if got := writableSeverity(test.reach); got != test.want {
			t.Errorf("writableSeverity(%s) = %s, want %s", test.reach, got, test.want)
		}
	}
	unowned := []struct {
		reach Reach
		want  Severity
	}{{RootAsset, High}, {ServiceAsset, Medium}, {UserAsset, Low}}
	for _, test := range unowned {
		if got := unownedSeverity(test.reach); got != test.want {
			t.Errorf("unownedSeverity(%s) = %s, want %s", test.reach, got, test.want)
		}
	}
}

func TestEdgeReach(t *testing.T) {
	file := func(mk func(*trust.Facts)) trust.Facts {
		facts := trust.Facts{Kind: trust.File}
		mk(&facts)
		return facts
	}
	cases := []struct {
		name string
		edge startup.Edge
		want Reach
	}{
		{"preload maps to the kernel", startup.Edge{Kind: startup.Preload}, KernelAsset},
		{"a setuid target reaches root", startup.Edge{
			TargetFacts: file(func(f *trust.Facts) { f.Setuid = true }),
		}, RootAsset},
		{"a capability target reaches root", startup.Edge{
			TargetFacts: file(func(f *trust.Facts) { f.Caps = true }),
		}, RootAsset},
		{"a root subject reaches root", startup.Edge{
			Subject: startup.Subject{Class: startup.AccountRoot},
		}, RootAsset},
		{"a login subject reaches root", startup.Edge{
			Subject: startup.Subject{Class: startup.AccountLogin},
		}, RootAsset},
		{"a loader preload reaches root", startup.Edge{
			Subject: startup.Subject{Class: startup.AccountAll},
		}, RootAsset},
		{"a dynamic user reaches a service", startup.Edge{
			Subject: startup.Subject{Class: startup.AccountDynamic},
		}, ServiceAsset},
		{"a named account reaches the user", startup.Edge{
			Subject: startup.Account("alice"),
		}, UserAsset},
		{"a unit that names root reaches root", startup.Edge{
			Subject: startup.Account("root"),
		}, RootAsset},
	}
	for _, test := range cases {
		if got := edgeReach(test.edge); got != test.want {
			t.Errorf("%s: edgeReach = %s, want %s", test.name, got, test.want)
		}
	}
}

func TestWritableEdge(t *testing.T) {
	base := startup.Edge{Subject: startup.Subject{Class: startup.AccountRoot}}
	if !writableEdge(startup.Edge{
		Subject:      base.Subject,
		TriggerFacts: trust.Facts{Writable: true},
	}) {
		t.Error("a writable trigger end must be a writable edge")
	}
	if !writableEdge(startup.Edge{
		Subject:     base.Subject,
		TargetFacts: trust.Facts{ParentOpen: true},
	}) {
		t.Error("an open directory above the target must be a writable edge")
	}
	// Parent-writable counts only for subjects that act as root: a user
	// account owning its own home directory is the normal shape.
	owned := trust.Facts{ParentWritable: true}
	if !writableEdge(startup.Edge{Subject: base.Subject, TriggerFacts: owned}) {
		t.Error("a root subject in a parent-writable directory is a writable edge")
	}
	if writableEdge(startup.Edge{Subject: startup.Account("alice"), TriggerFacts: owned}) {
		t.Error("a named account in its own parent-writable directory is not")
	}
	if writableEdge(startup.Edge{Subject: startup.Account("alice")}) {
		t.Error("clean facts are not a writable edge")
	}
}

func TestUnownedTarget(t *testing.T) {
	unowned := trust.Facts{
		Kind: trust.File, PackageKnown: true, Executable: true,
	}
	if !unownedTarget(startup.Edge{TargetFacts: unowned}) {
		t.Error("an unowned executable target must be reported")
	}
	if !unownedTarget(startup.Edge{
		TargetFacts: trust.Facts{Kind: trust.File, PackageKnown: true},
		Kind:        startup.Preload,
	}) {
		t.Error("an unowned preload target must be reported")
	}
	if !unownedTarget(startup.Edge{
		TargetFacts: trust.Facts{Kind: trust.File, PackageKnown: true},
		Kind:        startup.Library,
	}) {
		t.Error("an unowned library target must be reported")
	}
	owned := unowned
	owned.Package = "bash"
	if unownedTarget(startup.Edge{TargetFacts: owned}) {
		t.Error("a package-owned target is not unowned")
	}
	unknown := trust.Facts{Kind: trust.File, Executable: true}
	if unownedTarget(startup.Edge{TargetFacts: unknown}) {
		t.Error("a database that could not answer is not an unowned fact")
	}
	missing := unowned
	missing.Kind = trust.Missing
	if unownedTarget(startup.Edge{TargetFacts: missing}) {
		t.Error("a missing path is not an unowned file")
	}
}

func TestSurfaceAndPathScope(t *testing.T) {
	if !surfaceInScope(startup.SurfaceCron, Filter{}) {
		t.Error("a nil surface filter reads every surface")
	}
	narrow := Filter{Surfaces: surfacePtr(startup.AllScope())}
	if !surfaceInScope(startup.SurfaceCron, narrow) {
		t.Error("the persistence word stands for every activation surface")
	}
	one := Filter{Surfaces: surfacePtr(startup.Systemd)}
	if surfaceInScope(startup.SurfaceCron, one) {
		t.Error("a named surface must exclude the others")
	}
	wide := Filter{Paths: []string{"/etc"}, ExcludePaths: []string{"/etc/alternatives"}}
	if !pathInScope("/etc/pam.d/common-auth", wide) {
		t.Error("a path under the scope root is in scope")
	}
	if !pathInScope("/etc", wide) {
		t.Error("the scope root itself is in scope")
	}
	if pathInScope("/etc/alternatives/x", wide) {
		t.Error("an excluded path is out of scope even under the root")
	}
	if pathInScope("/var", wide) {
		t.Error("a path outside the scope roots is out of scope")
	}
	if !pathInScope("", Filter{}) {
		t.Error("an empty path with no path scope is in scope")
	}
	if !pathInScope("/etc/passwd", Filter{Paths: []string{"/"}}) {
		t.Error("the root path scope covers every absolute path")
	}
	if pathInScope("/etc/passwd", Filter{ExcludePaths: []string{"/"}}) {
		t.Error("the root exclusion removes every path")
	}
}

func TestUnitScope(t *testing.T) {
	if got := activationUnit("/etc/systemd/system/agent.service.d/50-x.conf"); got != "agent.service" {
		t.Errorf("activationUnit(drop-in) = %q, want the unit the drop-in belongs to", got)
	}
	if got := activationUnit("/etc/systemd/system/agent.service"); got != "agent.service" {
		t.Errorf("activationUnit(unit) = %q", got)
	}
	if got := templateUnit("getty@tty1.service"); got != "getty@.service" {
		t.Errorf("templateUnit(instance) = %q", got)
	}
	if got := templateUnit("sshd.service"); got != "sshd.service" {
		t.Errorf("templateUnit(plain) = %q", got)
	}
	filter := Filter{Units: map[string]bool{"sshd.service": true}}
	if !unitInScope("/etc/systemd/system/sshd.service.d/50-x.conf", filter) {
		t.Error("a drop-in of a selected unit is in unit scope")
	}
	if unitInScope("/etc/systemd/system/other.service", filter) {
		t.Error("another unit is out of unit scope")
	}
	if !unitInScope("/etc/profile", Filter{}) {
		t.Error("no unit scope reads every trigger")
	}
}

func TestCapabilityFindingUsesTheEffectiveUID(t *testing.T) {
	snapshot := &Snapshot{Processes: []Process{{
		PID: 424242, UID: 1000, EUID: 0, CapEff: 1 << 7,
	}}}
	var findings []Finding
	judgeLoaders(&judgePass{
		snapshot: snapshot,
		a:        newAssessor(snapshot),
		filter:   Filter{},
		add:      func(f Finding) { findings = append(findings, f) },
	})
	for _, finding := range findings {
		if finding.Class == "process-capability" {
			t.Errorf("setuid-root process was called non-root: %+v", finding)
		}
	}
}

func TestInterpreterClassNormalizesVersionSuffixes(t *testing.T) {
	cases := map[string]string{
		"/usr/bin/python3.12": "python",
		"/usr/bin/perl5.36":   "perl",
		"/usr/bin/ruby3.2":    "ruby",
	}
	for path, want := range cases {
		got, ok := interpreterClass(Process{Exe: path})
		if !ok || got != want {
			t.Errorf("interpreterClass(%q) = %q, %v; want %q", path, got, ok, want)
		}
	}
}

func TestExcludedOnlyPIDKeepsTheComplement(t *testing.T) {
	snapshot := &Snapshot{
		Sockets: []Socket{
			{Proto: "tcp", State: "LISTEN", Local: ":22", PID: 10},
			{Proto: "tcp", State: "LISTEN", Local: ":80", PID: 11},
		},
		Connections: []Connection{
			{PID: 10, PIDs: []int{10}},
			{PID: 11, PIDs: []int{11}},
		},
		Processes: []Process{{PID: 10}, {PID: 11}},
	}
	view := NewView(snapshot, Filter{ExcludePIDs: map[int]bool{10: true}})
	if len(view.Sockets) != 1 || view.Sockets[0].PID != 11 {
		t.Errorf("excluded-only pid sockets = %+v, want pid 11", view.Sockets)
	}
	if len(view.Connections) != 1 || view.Connections[0].PID != 11 {
		t.Errorf("excluded-only pid connections = %+v, want pid 11", view.Connections)
	}
}

func TestPathExclusionDropsBothEndsOfAnActivation(t *testing.T) {
	edges := []startup.Edge{{
		Surface: startup.SurfaceCron, Trigger: "/etc/cron.d/x", Target: "/etc/cron.d/y",
		Kind: startup.Exec, Mechanism: "run",
	}}
	filter := Filter{Paths: []string{"/etc"}, ExcludePaths: []string{"/etc/cron.d/x"}}
	if got := scopeActivations(edges, filter); len(got) != 0 {
		t.Errorf("activation with an excluded trigger stayed: %+v", got)
	}
}

func TestServiceCoverage(t *testing.T) {
	snapshot := &Snapshot{
		Services: []Service{
			{Unit: "sshd.service", Active: "active"},
			{Unit: "getty@tty1.service", Active: "active"},
			{Unit: "apache2.service", Active: "inactive"},
		},
		Activations: []startup.Edge{{Trigger: "/etc/systemd/system/sshd.service"}},
	}
	lines := serviceCoverage(snapshot)
	if len(lines) != 1 || !strings.Contains(lines[0].Detail, "getty@tty1.service") {
		t.Errorf("coverage = %v, want the instance unit whose template was not read", lines)
	}
	snapshot.Activations = append(snapshot.Activations, startup.Edge{Trigger: "/etc/systemd/system/getty@.service"})
	if lines := serviceCoverage(snapshot); len(lines) != 0 {
		t.Errorf("coverage = %v, want quiet once the template is read", lines)
	}
}

func TestAuthorityReach(t *testing.T) {
	cases := []struct {
		name  string
		facts func(*trust.Facts)
		path  string
		want  Reach
	}{
		{"sudoers", func(f *trust.Facts) {}, "/etc/sudoers", RootAsset},
		{"a sudoers drop-in", func(f *trust.Facts) {}, "/etc/sudoers.d/99-x", RootAsset},
		{"a host key", func(f *trust.Facts) {}, "/etc/ssh/ssh_host_ed25519_key", RootAsset},
		{"a root-owned setuid binary", func(f *trust.Facts) { f.Setuid, f.RootOwned = true, true }, "/usr/bin/su", RootAsset},
		{"a capability binary", func(f *trust.Facts) { f.Caps = true }, "/usr/bin/ping", RootAsset},
		{"a setgid root group", func(f *trust.Facts) { f.Setgid, f.Group = true, 0 }, "/usr/bin/wall", RootAsset},
		{"a setgid service group", func(f *trust.Facts) { f.Setgid, f.Group = true, 33 }, "/usr/bin/x", ServiceAsset},
		{"an admin-layer root file", func(f *trust.Facts) { f.RootOwned, f.AdminLayer = true, true }, "/usr/local/bin/x", RootAsset},
		{"a plain file", func(f *trust.Facts) {}, "/home/alice/x", UserAsset},
	}
	for _, test := range cases {
		facts := trust.Facts{Path: test.path}
		test.facts(&facts)
		if got := authorityReach(facts); got != test.want {
			t.Errorf("%s: authorityReach = %s, want %s", test.name, got, test.want)
		}
	}
}

func TestProcessReachUsesTheEffectiveUID(t *testing.T) {
	if got := processReach(Process{UID: 1000, EUID: 0}); got != RootAsset {
		t.Errorf("a setuid-root process at user reach = %s, want root", got)
	}
	if got := processReach(Process{UID: 0, EUID: 0}); got != RootAsset {
		t.Errorf("root = %s", got)
	}
	if got := processReach(Process{UID: 33, EUID: 33}); got != ServiceAsset {
		t.Errorf("a service account = %s", got)
	}
	if got := processReach(Process{UID: 1000, EUID: -1}); got != UserAsset {
		t.Errorf("an unread effective uid falls back to the real uid: %s", got)
	}
}

func TestScopedSocketsFollowTheSelectedProcesses(t *testing.T) {
	snapshot := &Snapshot{
		Sockets: []Socket{
			{PID: 10, Proto: "tcp", Local: "10.0.0.2:22"},
			{PID: 20, Proto: "tcp", Local: "10.0.0.2:80"},
		},
		Processes: []Process{
			{PID: 10, Exe: "/usr/sbin/sshd"},
			{PID: 20, Unit: "getty@tty1.service", Exe: "/sbin/agetty"},
		},
	}
	view := NewView(snapshot, Filter{PIDs: map[int]bool{20: true}})
	if len(view.Sockets) != 1 || view.Sockets[0].PID != 20 {
		t.Errorf("pid scope kept %v", view.Sockets)
	}
	view = NewView(snapshot, Filter{Units: map[string]bool{"getty@.service": true}})
	if len(view.Sockets) != 1 || view.Sockets[0].PID != 20 {
		t.Errorf("unit scope missed the instance unit's socket: %v", view.Sockets)
	}
	view = NewView(snapshot, Filter{})
	if len(view.Sockets) != 2 {
		t.Errorf("an unscoped view changed the socket table: %v", view.Sockets)
	}
}

func TestProcessContextNamesTheLiveFacts(t *testing.T) {
	lines := processContext(Process{Outbound: 2, Root: "/srv/jail", Seccomp: 2, NoNewPrivs: true})
	if len(lines) != 4 || !strings.Contains(lines[0], "2 established") ||
		!strings.Contains(lines[1], "/srv/jail") || !strings.Contains(lines[2], "mode 2") ||
		!strings.Contains(lines[3], "no_new_privs") {
		t.Errorf("processContext = %v", lines)
	}
	if lines := processContext(Process{}); len(lines) != 0 {
		t.Errorf("a plain process has no context: %v", lines)
	}
}

func TestCollectParentsAreTheAncestorChain(t *testing.T) {
	snapshot := &Snapshot{Objects: map[string]trust.Facts{
		"/usr/local/libexec/agent": {Path: "/usr/local/libexec/agent"},
		"/etc/pam.d/common-auth":   {Path: "/etc/pam.d/common-auth"},
	}}
	parents := collectParents(snapshot)
	want := map[string]bool{
		"/usr/local/libexec": true, "/usr/local": true, "/usr": true,
		"/etc/pam.d": true, "/etc": true,
	}
	if len(parents) != len(want) {
		t.Errorf("parents = %v", parents)
	}
	for _, parent := range parents {
		if !want[parent] {
			t.Errorf("unexpected parent %q", parent)
		}
	}
}

// TestMountOverExecTreeFinding pins the row-level mount judgment: a network
// filesystem over an execution tree is a finding on its own, whatever the
// table's origin; a local row and a network mount over a data tree stay quiet.
func TestMountOverExecTreeFinding(t *testing.T) {
	fstab := pathFacts("/etc/fstab", 900, 0o644, 0)
	usr := pathFacts("/usr", 900, 0o755, 0)
	row := func(target, note string) startup.Edge {
		return startup.Edge{
			Surface: startup.SurfaceSystem, Phase: startup.BootEnabled, Subject: startup.Subject{Class: startup.AccountRoot},
			Trigger: fstab.Path, Target: target, Kind: startup.Config, Mechanism: "fstab",
			Note: note, TriggerFacts: fstab, TargetFacts: pathFacts(target, 900, 0o755, 0),
		}
	}
	snapshot := &Snapshot{
		Boundary:    boundary(),
		Objects:     map[string]trust.Facts{fstab.Path: fstab, "/usr": usr},
		Activations: []startup.Edge{row("/usr", "nfs4 rw,hard")},
	}
	report := Judge(snapshot, Filter{})
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %+v, want the mount finding", report.Findings)
	}
	finding := report.Findings[0]
	if finding.Class != "mount-exec-tree" || finding.Severity != High || finding.Reach != RootAsset {
		t.Errorf("finding = %+v, want mount-exec-tree high root", finding)
	}
	quiet := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{fstab.Path: fstab, "/usr": usr},
		Activations: []startup.Edge{
			row("/usr", "ext4 defaults"),
			row("/home/data", "nfs4 rw"),
		},
	}
	if report := Judge(quiet, Filter{}); len(report.Findings) != 0 {
		t.Errorf("findings = %+v, want a local row and a data-tree mount to stay quiet", report.Findings)
	}
}

// TestContextRiskRule pins the one context shape that is a finding: a
// ReadWritePaths that fences the unit in nowhere, or hands it a
// world-writable directory with no sticky bit. A sticky directory and any
// other context key stay profile-only.
func TestContextRiskRule(t *testing.T) {
	unit := pathFacts("/etc/systemd/system/agent.service", 900, 0o644, 0)
	root := pathFacts("/", 900, 0o755, 0)
	world := trust.Build("/var/tmp/share", trust.Attrs{Kind: trust.Dir, Mode: 0o777, UID: 0, Real: "/var/tmp/share"})
	sticky := trust.Build("/tmp", trust.Attrs{Kind: trust.Dir, Mode: os.ModeSticky | 0o777, UID: 0, Real: "/tmp"})
	context := func(mechanism, target string, facts trust.Facts) startup.Edge {
		return startup.Edge{
			Surface: startup.SurfaceSystemd, Phase: startup.BootEnabled, Subject: startup.Subject{Class: startup.AccountRoot},
			Trigger: unit.Path, Target: target, Kind: startup.Config, Mechanism: startup.Mechanism(mechanism),
			Context: true, TriggerFacts: unit, TargetFacts: facts,
		}
	}
	snapshot := &Snapshot{
		Boundary: boundary(),
		Objects: map[string]trust.Facts{
			unit.Path: unit, "/": root, "/var/tmp/share": world, "/tmp": sticky,
		},
		Activations: []startup.Edge{
			context("ReadWritePaths", "/", root),
			context("ReadWritePaths", "/var/tmp/share", world),
			context("ReadWritePaths", "/tmp", sticky),
			context("WorkingDirectory", "/", root),
		},
	}
	report := Judge(snapshot, Filter{})
	if len(report.Findings) != 2 {
		t.Fatalf("findings = %+v, want the root and the non-sticky world-writable declaration", report.Findings)
	}
	high, medium := false, false
	for _, finding := range report.Findings {
		if finding.Class != "activation-context" {
			t.Errorf("finding class = %s, want activation-context", finding.Class)
			continue
		}
		if finding.Path != unit.Path {
			t.Errorf("finding path = %s, want the declaring unit %s", finding.Path, unit.Path)
		}
		switch finding.Severity {
		case High:
			high = true
			if !strings.HasSuffix(finding.Detail, "writes /") {
				t.Errorf("the root declaration detail = %q, want it to end in \"writes /\"", finding.Detail)
			}
		case Medium:
			medium = true
			if !strings.Contains(finding.Detail, "/var/tmp/share") {
				t.Errorf("the world-writable declaration detail = %q, want the written path", finding.Detail)
			}
		}
		if finding.Path == "/" {
			t.Errorf("a context finding names the root as its object: %+v", finding)
		}
	}
	if !high || !medium {
		t.Errorf("findings = %+v, want one high root declaration and one medium world-writable one", report.Findings)
	}
}

// TestJudgeDivertedTargetReadsMedium pins the diversion tier: a target the
// package database knows as a local diversion reads one tier below a file no
// package has ever heard of.
func TestJudgeDivertedTargetReadsMedium(t *testing.T) {
	trigger := pathFacts("/etc/pam.d/common-auth", 900, 0o644, 0)
	target := trust.Build("/lib/security/pam_local.so", trust.Attrs{
		Kind: trust.File, Mode: 0o644, UID: 0, Real: "/lib/security/pam_local.so",
		CTime: 900, PackageKnown: true, Diverted: true,
	})
	snapshot := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{trigger.Path: trigger, target.Path: target},
		Activations: []startup.Edge{{
			Surface: startup.SurfacePAM, Phase: startup.Login, Subject: startup.Subject{Class: startup.AccountRoot},
			Trigger: trigger.Path, Target: target.Path, Kind: startup.Library, Mechanism: "pam",
			TriggerFacts: trigger, TargetFacts: target,
		}},
	}
	report := Judge(snapshot, Filter{})
	for _, finding := range report.Findings {
		if finding.Class == "unowned-target" && finding.Severity != Medium {
			t.Errorf("a diverted target = %s, want medium", finding.Severity)
		}
	}
}

// TestJudgeAuthorityOutsideTiersByPackage pins the outside rule: a setuid
// object no package has heard of reads High, one a package installed in an
// administrator tree reads Medium with the owner named.
func TestJudgeAuthorityOutsideTiersByPackage(t *testing.T) {
	unowned := pathFacts("/opt/tool", 900, 0o4755, 0)
	owned := trust.Build("/opt/admin-tool", trust.Attrs{
		Kind: trust.File, Mode: 0o4755, UID: 0, Real: "/opt/admin-tool",
		CTime: 900, Package: "admin-tools", PackageKnown: true,
	})
	snapshot := &Snapshot{
		Boundary:  boundary(),
		Objects:   map[string]trust.Facts{unowned.Path: unowned, owned.Path: owned},
		Authority: []string{unowned.Path, owned.Path},
	}
	report := Judge(snapshot, Filter{})
	seen := map[string]Severity{}
	for _, finding := range report.Findings {
		if finding.Class == "authority-outside" {
			seen[finding.Path] = finding.Severity
		}
	}
	if seen[unowned.Path] != High {
		t.Errorf("unowned outside = %s, want high", seen[unowned.Path])
	}
	if seen[owned.Path] != Medium {
		t.Errorf("package-owned outside = %s, want medium", seen[owned.Path])
	}
}

// TestClockSkewTiers pins the skew ladder: drift of minutes to a few hours is
// Medium, a lie of more than six hours is the hostile shape and reads High.
func TestClockSkewTiers(t *testing.T) {
	clock := func(skew time.Duration) ClockState {
		now := time.Unix(2000, 0)
		boot := now.Add(-skew).Add(-time.Hour)
		return ClockState{Now: now, Boot: boot, Uptime: time.Hour, Skew: skew,
			Reading: "kernel boot + uptime vs wall clock"}
	}
	judged := func(skew time.Duration) Severity {
		snapshot := &Snapshot{Boundary: boundary(), Clock: clock(skew)}
		report := Judge(snapshot, Filter{})
		for _, finding := range report.Findings {
			if finding.Class == "clock-skew" {
				return finding.Severity
			}
		}
		return Info
	}
	if got := judged(2 * time.Hour); got != Medium {
		t.Errorf("a two-hour skew = %s, want medium", got)
	}
	if got := judged(7 * time.Hour); got != High {
		t.Errorf("a seven-hour skew = %s, want high", got)
	}
	if got := judged(30 * time.Second); got != Info {
		t.Errorf("a wobble inside the tolerance = %s, want quiet", got)
	}
}
