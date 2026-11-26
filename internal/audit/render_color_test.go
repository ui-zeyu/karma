package audit

// The evidence tables' hues: every panel states the judgment it carries in the
// one palette, and the rows a data format cannot read (JSON) carry none.

import (
	"bytes"
	"strings"
	"testing"

	"karma/internal/trust"
)

func TestConnectionRowsHueTheInterpreterAndThePeer(t *testing.T) {
	snapshot := &Snapshot{
		Boundary: boundary(),
		Processes: []Process{
			{PID: 100, Comm: "bash", Exe: "/usr/bin/bash"},
			{PID: 200, Comm: "sshd", Exe: "/usr/sbin/sshd", Unit: "ssh.service"},
		},
		Connections: []Connection{
			{Proto: "tcp", Local: "10.0.0.1:22", Peer: "203.0.113.5:4000", PID: 100, PIDs: []int{100}, Comm: "bash"},
			{Proto: "tcp", Local: "10.0.0.1:22", Peer: "198.51.100.9:4000", PID: 200, PIDs: []int{200}, Comm: "sshd"},
		},
	}
	view := NewView(snapshot, Filter{})
	rows := connectionRows(view, RenderOptions{Color: true})
	shell := rowContaining(t, rows, "bash")
	if !strings.Contains(shell, fg(hueAlert)) {
		t.Errorf("the interpreter's connection is not in the alert hue: %q", shell)
	}
	if !strings.Contains(shell, fg(hueInformation)) {
		t.Errorf("the established peer is not in the information hue: %q", shell)
	}
	service := rowContaining(t, rows, "sshd")
	if strings.Contains(service, fg(hueAlert)) {
		t.Errorf("a service's connection wears the interpreter hue: %q", service)
	}
	for _, row := range connectionRows(view, RenderOptions{}) {
		if strings.Contains(row, "\x1b[") {
			t.Errorf("an uncolored connection row carries an escape: %q", row)
		}
	}
}

func TestKernelRowsHueStateTaintOriginAndHiddenItems(t *testing.T) {
	snapshot := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{},
		Kernel: KernelState{
			Collected: true,
			Modules: []KernelModule{{
				Name: "xt_nat", Used: 10, State: "Live", Taint: "O",
				File: "/lib/modules/x/xt_nat.ko", FileState: ModuleFileMapped,
				Facts: pathFacts("/lib/modules/x/xt_nat.ko", 1200, 0o644, 0),
			}},
			Hidden:     []HiddenModule{{Name: "rootkit", Views: []string{"/sys/module"}}},
			HiddenPIDs: []int{4242},
			Tainted:    1, TaintNames: []string{"O"},
		},
	}
	view := NewView(snapshot, Filter{})
	rows := kernelRows(view, RenderOptions{Color: true})
	module := rowContaining(t, rows, "xt_nat")
	for _, want := range []int{hueLive, hueCaution, hueAlert} {
		if !strings.Contains(module, fg(want)) {
			t.Errorf("the module row misses hue %d: %q", want, module)
		}
	}
	if row := rowContaining(t, rows, "hidden module"); !strings.Contains(row, fg(hueAlert)) {
		t.Errorf("a hidden module is not in the alert hue: %q", row)
	}
	if row := rowContaining(t, rows, "hidden pid"); !strings.Contains(row, fg(hueAlert)) {
		t.Errorf("a hidden pid is not in the alert hue: %q", row)
	}
	if row := rowContaining(t, rows, "taint 1"); !strings.Contains(row, fg(hueCaution)) {
		t.Errorf("the taint mask is not in the caution hue: %q", row)
	}
	for _, row := range kernelRows(view, RenderOptions{}) {
		if strings.Contains(row, "\x1b[") {
			t.Errorf("an uncolored module row carries an escape: %q", row)
		}
	}
}

func TestShowJSONCarriesNoHues(t *testing.T) {
	snapshot := &Snapshot{
		Boundary: boundary(),
		Processes: []Process{
			{PID: 100, Comm: "bash", Exe: "/usr/bin/bash"},
		},
		Connections: []Connection{
			{Proto: "tcp", Local: "10.0.0.1:22", Peer: "203.0.113.5:4000", PID: 100, PIDs: []int{100}, Comm: "bash"},
		},
	}
	view := NewView(snapshot, Filter{})
	section, ok := SectionFor("connections")
	if !ok {
		t.Fatal("the connections section is missing from the table")
	}
	var out bytes.Buffer
	if err := WriteShowJSON(&out, view, section, "connections", RenderOptions{Color: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Errorf("show JSON carries terminal escapes:\n%s", out.String())
	}
}

func rowContaining(t *testing.T, rows []string, want string) string {
	t.Helper()
	for _, row := range rows {
		if strings.Contains(row, want) {
			return row
		}
	}
	t.Fatalf("no row contains %q", want)
	return ""
}
