package audit

import (
	"testing"

	"karma/internal/startup"
)

func TestPlanCollectors(t *testing.T) {
	full := FullPlan()
	if !full.Has(DomainProcesses) || !full.Has(DomainNetwork) {
		t.Errorf("full plan skips processes or network")
	}
	services := Plan{Domains: DomainServices, Surfaces: map[string]bool{"systemd": true}}
	if services.Has(DomainProcesses) {
		t.Errorf("a services audit should not read /proc")
	}
	if scope := services.startupScope(); !scope.Systemd || scope.Profile {
		t.Errorf("services startup scope = %+v", scope)
	}
	files := Plan{Domains: DomainFiles, Surfaces: map[string]bool{"files": true}}
	if files.Has(DomainProcesses) {
		t.Errorf("a files audit should not read /proc")
	}
	if scope := files.startupScope(); scope != (startup.Scope{}) {
		t.Errorf("files startup scope is not empty: %+v", scope)
	}
}

func TestProfilePids(t *testing.T) {
	processes := []Process{
		{PID: 10, Unit: "ssh.service", Exe: "/usr/sbin/sshd"},
		{PID: 11, Unit: "docker.service", Exe: "/usr/bin/dockerd"},
		{PID: 12, Unit: "", Exe: "/opt/app/agent", Script: "/opt/app/run.sh"},
	}
	if pids := profilePids("ssh.service", processes); len(pids) != 1 || !pids[10] {
		t.Errorf("unit pids = %v", pids)
	}
	if pids := profilePids("11", processes); len(pids) != 1 || !pids[11] {
		t.Errorf("pid pids = %v", pids)
	}
	if pids := profilePids("/opt/app/agent", processes); len(pids) != 1 || !pids[12] {
		t.Errorf("path pids = %v", pids)
	}
	if pids := profilePids("pid:12", processes); len(pids) != 1 || !pids[12] {
		t.Errorf("prefixed pid pids = %v", pids)
	}
}
