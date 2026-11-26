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

func TestSeedPidsFollowTheSelector(t *testing.T) {
	processes := []Process{
		{PID: 10, Unit: "ssh.service", Exe: "/usr/sbin/sshd"},
		{PID: 11, Unit: "docker.service", Exe: "/usr/bin/dockerd"},
		{PID: 12, Unit: "", Exe: "/opt/app/agent", Script: "/opt/app/run.sh"},
	}
	seed := func(word string) GraphSeed {
		parsed, err := ParseGraphSeed(word)
		if err != nil {
			t.Fatalf("ParseGraphSeed(%q): %v", word, err)
		}
		return parsed
	}
	if pids := seedPids(seed("ssh.service"), processes); len(pids) != 1 || !pids[10] {
		t.Errorf("unit pids = %v", pids)
	}
	if pids := seedPids(seed("11"), processes); len(pids) != 1 || !pids[11] {
		t.Errorf("pid pids = %v", pids)
	}
	if pids := seedPids(seed("/opt/app/agent"), processes); len(pids) != 1 || !pids[12] {
		t.Errorf("path pids = %v", pids)
	}
	if pids := seedPids(seed("pid:12"), processes); len(pids) != 1 || !pids[12] {
		t.Errorf("prefixed pid pids = %v", pids)
	}
	if pids := seedPids(seed("pkg:openssh"), processes); len(pids) != 0 {
		t.Errorf("package pids = %v", pids)
	}
}

func TestParseGraphSeedReadsOneGrammar(t *testing.T) {
	cases := []struct {
		word  string
		kind  string
		value string
	}{
		{"unit:x.service", "unit", "x.service"},
		{"x.service", "unit", "x.service"},
		{"getty@.service", "unit", "getty@.service"},
		{"pid:12", "pid", "12"},
		{"12", "pid", "12"},
		{"/etc/passwd", "path", "/etc/passwd"},
		{"path:/etc/passwd", "path", "/etc/passwd"},
		{"pkg:openssh", "package", "openssh"},
		{"openssh", "package", "openssh"},
	}
	for _, test := range cases {
		seed, err := ParseGraphSeed(test.word)
		if err != nil {
			t.Errorf("ParseGraphSeed(%q): %v", test.word, err)
			continue
		}
		if seed.Kind != test.kind || seed.Value != test.value {
			t.Errorf("ParseGraphSeed(%q) = %+v, want %s %q", test.word, seed, test.kind, test.value)
		}
	}
	for _, word := range []string{"unit:", "pid:", "path:relative", "pkg:", "path:"} {
		if _, err := ParseGraphSeed(word); err == nil {
			t.Errorf("ParseGraphSeed(%q) was accepted", word)
		}
	}
}
