package audit

// The view is where the scope filters the inventories once. Its rules are the
// ones the report states: a row is kept when the scope names a relation the
// row answers, and the surface words the judgment shares gate the panels the
// surface scope can judge.

import (
	"testing"

	"karma/internal/startup"
)

func edge(surface startup.Surface, trigger, target string) startup.Edge {
	return startup.Edge{Surface: surface, Trigger: trigger, Target: target, Kind: startup.Exec}
}

func TestViewNarrowsRowsByTheRelationsTheyAnswer(t *testing.T) {
	snapshot := &Snapshot{
		Boundary: boundary(),
		Processes: []Process{
			{PID: 1, Unit: "init"},
			{PID: 10, Unit: "ssh.service", Exe: "/usr/sbin/sshd"},
			{PID: 11, Unit: "docker.service", Exe: "/usr/bin/dockerd"},
		},
		Services: []Service{
			{Unit: "ssh.service", Active: "active"},
			{Unit: "docker.service", Active: "active"},
		},
		Sockets: []Socket{
			{Proto: "tcp", State: "LISTEN", Local: ":22", PID: 10},
			{Proto: "tcp", State: "LISTEN", Local: ":2375", PID: 11},
		},
		Connections: []Connection{
			{Proto: "tcp", Peer: "203.0.113.5:4000", PID: 10, PIDs: []int{10}},
			{Proto: "tcp", Peer: "198.51.100.9:4000", PID: 11, PIDs: []int{11}},
		},
		Activations: []startup.Edge{
			edge(startup.SurfaceSystemd, "/etc/systemd/system/ssh.service", "/usr/sbin/sshd"),
			edge(startup.SurfaceCron, "/etc/cron.d/backup", "/usr/local/bin/backup"),
		},
		Authority: []string{"/etc/passwd", "/usr/local/bin/tool"},
	}
	filter := Filter{Units: map[string]bool{"ssh.service": true}}
	view := NewView(snapshot, filter)
	if len(view.Services) != 1 || view.Services[0].Unit != "ssh.service" {
		t.Errorf("services = %+v", view.Services)
	}
	if len(view.Processes) != 1 || view.Processes[0].PID != 10 {
		t.Errorf("processes = %+v", view.Processes)
	}
	if len(view.Sockets) != 1 || view.Sockets[0].Local != ":22" {
		t.Errorf("sockets = %+v", view.Sockets)
	}
	if len(view.Connections) != 1 || view.Connections[0].Peer != "203.0.113.5:4000" {
		t.Errorf("connections = %+v", view.Connections)
	}
	if len(view.Activations) != 1 || view.Activations[0].Trigger != "/etc/systemd/system/ssh.service" {
		t.Errorf("activations = %+v", view.Activations)
	}
	// A unit names no authority file, so the walk is not filtered by it.
	if len(view.Authority) != 2 {
		t.Errorf("authority = %+v", view.Authority)
	}

	view = NewView(snapshot, Filter{PIDs: map[int]bool{11: true}})
	if len(view.Processes) != 1 || view.Processes[0].PID != 11 {
		t.Errorf("pid processes = %+v", view.Processes)
	}
	if len(view.Sockets) != 1 || view.Sockets[0].Local != ":2375" {
		t.Errorf("pid sockets = %+v", view.Sockets)
	}
	if len(view.Connections) != 1 || view.Connections[0].Peer != "198.51.100.9:4000" {
		t.Errorf("pid connections = %+v", view.Connections)
	}
	// A pid names no activation file and no unit, so neither inventory answers.
	if len(view.Activations) != 0 {
		t.Errorf("pid activations = %+v", view.Activations)
	}
	if len(view.Services) != 2 {
		t.Errorf("pid services = %+v", view.Services)
	}
}

func TestViewSurfaceScopeGatesThePanelsTheScopeJudges(t *testing.T) {
	snapshot := &Snapshot{
		Boundary: boundary(),
		Processes: []Process{
			{PID: 10, Unit: "ssh.service", Exe: "/usr/sbin/sshd"},
		},
		Authority:   []string{"/etc/passwd"},
		Activations: []startup.Edge{edge(startup.SurfaceSystemd, "/etc/systemd/system/ssh.service", "/usr/sbin/sshd")},
	}
	// A surface scope that does not select the activity or authority view
	// judges neither inventory, so the panels carry no rows.
	view := NewView(snapshot, Filter{Surfaces: map[string]bool{"systemd": true}})
	if len(view.Processes) != 0 {
		t.Errorf("processes = %+v", view.Processes)
	}
	if len(view.Authority) != 0 {
		t.Errorf("authority = %+v", view.Authority)
	}
	if len(view.Activations) != 1 {
		t.Errorf("activations = %+v", view.Activations)
	}
	// The surface words the audit names as views open their own panels.
	view = NewView(snapshot, Filter{Surfaces: map[string]bool{"activity": true, "authority": true}})
	if len(view.Processes) != 1 {
		t.Errorf("processes = %+v", view.Processes)
	}
	if len(view.Authority) != 1 {
		t.Errorf("authority = %+v", view.Authority)
	}
}

func TestSectionTableCarriesEveryShowWord(t *testing.T) {
	for _, word := range []string{
		"activation", "persistence", "boot", "login", "service", "device", "schedule",
		"process", "activity", "services", "listeners", "sockets", "listen",
		"connections", "connection", "network", "kernel", "authority", "mounts", "coverage",
	} {
		if _, ok := SectionFor(word); !ok {
			t.Errorf("show word %q is missing from the section table", word)
		}
	}
	if _, ok := SectionFor("unknown"); ok {
		t.Errorf("an unknown show word was accepted")
	}
	// Aliases print under the canonical panel the audit uses for the same
	// inventory, so a section's name cannot change what its rows say.
	cases := map[string]string{
		"listeners": "LISTEN", "sockets": "LISTEN", "listen": "LISTEN",
		"connections": "CONNECTION", "connection": "CONNECTION", "network": "CONNECTION",
		"boot": "ACTIVATION", "login": "ACTIVATION",
	}
	for word, want := range cases {
		section, _ := SectionFor(word)
		if section.Panel != want {
			t.Errorf("show %q prints %q, want %q", word, section.Panel, want)
		}
	}
	// Every section answers a collection plan that includes its own domains,
	// and the persistence sections read every surface.
	activation, _ := SectionFor("boot")
	if plan := activation.Plan(Plan{}); !plan.Has(DomainPersistence) || plan.Surfaces != nil {
		t.Errorf("activation plan = %+v", plan)
	}
	mounts, _ := SectionFor("mounts")
	if plan := mounts.Plan(Plan{}); plan.Has(DomainProcesses) {
		t.Errorf("mounts plan = %+v", plan)
	}
}

func TestGraphSpecPlanCarriesTheDomainsTheGraphReads(t *testing.T) {
	cases := map[string]Domain{
		"identity":  DomainBase | DomainIdentity,
		"network":   DomainBase | DomainProcesses | DomainNetwork,
		"packages":  DomainBase | DomainPackages,
		"boot":      DomainBase | DomainPersistence,
		"web":       DomainBase | DomainWeb,
		"kernel":    DomainBase | DomainKernel,
		"authority": DomainBase | DomainAuthority,
	}
	for word, want := range cases {
		module, spec, ok := GraphTarget(word)
		if !ok {
			t.Errorf("graph word %q is missing from the registry", word)
			continue
		}
		if plan := spec.Plan(module.Bit); plan.Domains != want {
			t.Errorf("graph %q plan domains = %b, want %b", word, plan.Domains, want)
		}
	}
	if _, _, ok := GraphTarget("unknown"); ok {
		t.Errorf("an unknown graph word was accepted")
	}
	// The boot graph reads every activation surface.
	_, spec, _ := GraphTarget("boot")
	if plan := spec.Plan(DomainPersistence); plan.Surfaces != nil {
		t.Errorf("boot plan surfaces = %+v", plan.Surfaces)
	}
}
