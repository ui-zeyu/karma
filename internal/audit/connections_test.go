package audit

import (
	"testing"

	"karma/internal/trust"
)

func processFixture(pid, uid int, exe, comm, unit string) Process {
	return Process{
		PID: pid, UID: uid, Exe: exe, Comm: comm, Unit: unit,
		Cmdline: exe,
	}
}

func TestInterpreterClass(t *testing.T) {
	if _, ok := interpreterClass(processFixture(1, 0, "/bin/bash", "bash", "")); !ok {
		t.Errorf("bash was not an interpreter")
	}
	if _, ok := interpreterClass(processFixture(1, 0, "/usr/bin/nc", "nc", "")); !ok {
		t.Errorf("nc was not a socket interpreter")
	}
	if _, ok := interpreterClass(processFixture(1, 0, "/usr/bin/python3", "python3", "")); !ok {
		t.Errorf("inline python was not an interpreter")
	}
	scripted := processFixture(1, 0, "/usr/bin/python3", "python3", "")
	scripted.Script = "/opt/job.py"
	if _, ok := interpreterClass(scripted); ok {
		t.Errorf("a scripted python job read as an inline reverse shell")
	}
	if _, ok := interpreterClass(processFixture(1, 0, "/usr/sbin/sshd", "sshd", "")); ok {
		t.Errorf("sshd read as an interpreter")
	}
}

func TestJudgeInterpreterConnection(t *testing.T) {
	snapshot := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{},
		Processes: []Process{
			processFixture(10, 0, "/bin/bash", "bash", ""),
			processFixture(11, 0, "/usr/bin/python3", "python3", "app.service"),
		},
		Connections: []Connection{
			{PID: 10, Proto: "tcp", Local: "10.0.0.1:50000", Peer: "203.0.113.9:4444", Comm: "bash"},
			{PID: 11, Proto: "tcp", Local: "10.0.0.1:50001", Peer: "10.0.0.2:5432", Comm: "python3"},
		},
		Sockets: []Socket{{PID: 10, Proto: "tcp", State: "LISTEN", Local: "0.0.0.0:9001", Comm: "bash"}},
	}
	report := Judge(snapshot, Filter{})
	var socketFinding, listenerFinding bool
	for _, finding := range report.Findings {
		switch finding.Class {
		case "interpreter-socket":
			socketFinding = true
			if finding.Severity != Critical || len(finding.Trace) < 3 {
				t.Errorf("socket finding = %+v", finding)
			}
		case "interpreter-listener":
			listenerFinding = true
		case "interpreter-socket-python3":
			t.Errorf("unit-managed python read as a reverse shell: %+v", finding)
		}
	}
	if !socketFinding || !listenerFinding {
		t.Errorf("findings = %+v", report.Findings)
	}
}

func TestBadLibraryPathAndCapabilities(t *testing.T) {
	for _, value := range []string{":", "/a:", "/a::/b", ".", "/a:."} {
		if !badLibraryPath(value) {
			t.Errorf("badLibraryPath(%q) = false", value)
		}
	}
	if badLibraryPath("/usr/local/lib:/usr/lib") {
		t.Errorf("a normal library path read as bad")
	}
	names := processCapabilities(1<<21 | 1<<7 | 1<<0)
	if len(names) != 2 || names[0] != "cap_setuid" || names[1] != "cap_sys_admin" {
		t.Errorf("capabilities = %v", names)
	}
}
