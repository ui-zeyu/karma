package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"karma/internal/trust"
)

const (
	testHash = "d41d8cd98f00b204e9800998ecf8427e"
	evilHash = "0123456789abcdef0123456789abcdef"
)

func pkgFacts(path string, ctime int64, pkg string) trust.Facts {
	return trust.Build(path, trust.Attrs{
		Kind: trust.File, Mode: 0o755, UID: 0, Real: path, CTime: ctime,
		Package: pkg, PackageKnown: true,
	})
}

func TestParsePackageLogLineReadsBothSpellings(t *testing.T) {
	cases := []struct {
		line string
		pkg  string
		day  int
	}{
		{"2026-11-24 22:32:00 install coreutils:amd64 9.1-1", "coreutils", 24},
		{"2026-11-24 22:33:00 status installed coreutils:amd64 9.1-1", "coreutils", 24},
		{"2026-11-24 22:34:00 trigproc libc6:amd64 2.36", "libc6", 24},
	}
	for _, test := range cases {
		pkg, stamp, ok := parsePackageLogLine(test.line)
		if !ok || pkg != test.pkg || stamp.Local().Day() != test.day {
			t.Errorf("%q: pkg=%q stamp=%v ok=%t", test.line, pkg, stamp, ok)
		}
	}
	want, _ := time.ParseInLocation(stampLayout, "2026-11-24 22:32:00", time.Local)
	_, stamp, _ := parsePackageLogLine(cases[0].line)
	if !stamp.Equal(want) {
		t.Errorf("stamp = %v, want local %v", stamp, want)
	}
	for _, line := range []string{"garbage", "2026-11-24 22:32:00 status", "2026-11-24 x install pkg"} {
		if _, _, ok := parsePackageLogLine(line); ok {
			t.Errorf("%q parsed as a transaction", line)
		}
	}
}

func TestJoinContentSurvivesTheUsrmerge(t *testing.T) {
	expected := map[string]ledgerEntry{
		"usr/bin/ls": {pkg: "coreutils", hash: testHash},
		"bin/ls":     {pkg: "oldpkg", hash: testHash},
	}
	verify := joinContent(map[string]string{
		"/usr/bin/ls": testHash,
		"/bin/ls":     evilHash,
	}, expected)
	if got := verify["/usr/bin/ls"]; got.State != Verified || got.Package != "coreutils" {
		t.Errorf("usr spelling = %+v", got)
	}
	if got := verify["/bin/ls"]; got.State != Mismatched || got.Package != "oldpkg" {
		t.Errorf("pre-merge spelling = %+v", got)
	}
	verify = joinContent(map[string]string{"/opt/tool": testHash}, expected)
	if got := verify["/opt/tool"]; got.State != Unverified {
		t.Errorf("unknown file = %+v", got)
	}
}

func TestReadDpkgLedgerAndHashFiles(t *testing.T) {
	root := t.TempDir()
	info := filepath.Join(root, "info")
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(info, 0o755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "bin", "ls")
	if err := os.WriteFile(binary, []byte("ELF"), 0o755); err != nil {
		t.Fatal(err)
	}
	hash, ok := hashFile(binary)
	if !ok || len(hash) != 32 {
		t.Fatalf("hashFile = %q %t", hash, ok)
	}
	stripped := strings.TrimPrefix(binary, "/")
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(info, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("coreutils.md5sums", hash+"  "+stripped+"\n")
	write("coreutils.list", "/bin\n"+binary+"\n")
	write("bash.conffiles", "/etc/bash.bashrc\n")
	write("bash.postinst", "#!/bin/sh\n")

	expected, conffiles, rows, ok := readDpkgLedger(t.Context(), info, map[string]bool{"coreutils": true, "bash": true})
	if !ok {
		t.Fatal("readDpkgLedger answered not-ok for a dpkg info dir")
	}
	if got := expected[stripped]; got.pkg != "coreutils" || got.hash != hash {
		t.Errorf("expected[%s] = %+v", stripped, got)
	}
	if len(expected) != 1 {
		t.Errorf("expected = %v, want only coreutils' entry", expected)
	}
	if !conffiles["/etc/bash.bashrc"] {
		t.Errorf("conffiles = %v", conffiles)
	}
	stamped := 0
	for _, row := range rows {
		if row.Pkg == "coreutils" {
			stamped++
		}
	}
	if stamped != 2 {
		t.Errorf("ledger stamps for coreutils = %d, want list+md5sums", stamped)
	}

	actual := hashFiles(t.Context(), map[string]trust.Facts{
		binary: pkgFacts(binary, 900, "coreutils"),
	})
	if actual[binary] != hash {
		t.Errorf("hashFiles = %v", actual)
	}
	verify := joinContent(actual, expected)
	if content := verify[binary]; content.State != Verified || content.Package != "coreutils" {
		t.Errorf("content = %+v, want verified against coreutils", content)
	}
}

func TestLedgerTamperNeedsALaterWriteAndAnOutlier(t *testing.T) {
	// The ledger's typical write is ~450; the package's last transaction is
	// 500. A stamp at 600 moved past the transaction but sits with the
	// baseline — an image build moving every file at once — and passes. Only
	// the outlier at 22700 reads as tampered, and a package with no recorded
	// transaction cannot be judged at all.
	times := map[string]time.Time{"bash": time.Unix(500, 0)}
	rows := []ledgerFile{
		{Pkg: "bash", Stamp: time.Unix(400, 0), Path: "/i/1"},
		{Pkg: "bash", Stamp: time.Unix(450, 0), Path: "/i/2"},
		{Pkg: "bash", Stamp: time.Unix(460, 0), Path: "/i/3"},
		{Pkg: "bash", Stamp: time.Unix(600, 0), Path: "/i/4"},
		{Pkg: "bash", Stamp: time.Unix(22700, 0), Path: "/i/5"},
		{Pkg: "unknown", Stamp: time.Unix(9000, 0), Path: "/i/6"},
	}
	tampered := ledgerTamper(times, rows)
	if len(tampered) != 1 || tampered[0].Path != "/i/5" {
		t.Errorf("tampered = %+v, want only the outlier", tampered)
	}
	baseline := medianStamp(rows)
	if baseline.Unix() != 600 {
		t.Errorf("baseline = %v, want 600", baseline)
	}
	if _, ok := packageLogTamper(times, time.Unix(700, 0), baseline); ok {
		t.Errorf("a log write 200s after the newest entry read as tampered")
	}
	if _, ok := packageLogTamper(times, time.Unix(5000, 0), baseline); ok {
		t.Errorf("a log write past the newest entry but with the baseline read as tampered")
	}
	if row, ok := packageLogTamper(times, time.Unix(40000, 0), baseline); !ok || row.Pkg != logLedgerPkg {
		t.Errorf("a log rewrite days past the newest entry passed: %+v %t", row, ok)
	}
}

func TestParseRpmVerifyLine(t *testing.T) {
	path, flags, conffile, absent, ok := parseRpmVerifyLine("SM5....T.  /usr/bin/x")
	if !ok || path != "/usr/bin/x" || flags != "SM5....T." || conffile || absent {
		t.Errorf("content row = %q %q %t %t %t", path, flags, conffile, absent, ok)
	}
	path, _, conffile, absent, ok = parseRpmVerifyLine("..5....T.  c /etc/hosts")
	if !ok || path != "/etc/hosts" || !conffile || absent {
		t.Errorf("config row = %q %t %t %t", path, conffile, absent, ok)
	}
	path, _, _, absent, ok = parseRpmVerifyLine("missing   /usr/bin/y")
	if !ok || path != "/usr/bin/y" || !absent {
		t.Errorf("missing row = %q %t %t", path, absent, ok)
	}
	if _, _, _, _, ok := parseRpmVerifyLine("unparseable junk here"); ok {
		t.Errorf("junk parsed as a verify row")
	}
}

func TestMountTableAnswersLongestPrefix(t *testing.T) {
	mounts := buildMountTable([]Mount{
		{FSType: "ext4", Path: "/"},
		{FSType: "tmpfs", Path: "/dev/shm"},
		{FSType: "overlay", Path: "/var/lib/docker"},
	})
	if mount, ok := mounts.mount("/dev/shm/payload"); !ok || !volatileMount(mount) {
		t.Errorf("/dev/shm mount = %+v %t", mount, ok)
	}
	if mount, ok := mounts.mount("/usr/bin/ls"); !ok || volatileMount(mount) {
		t.Errorf("/ mount = %+v %t", mount, ok)
	}
	if _, ok := mounts.mount("/var/lib/docker/overlay2/x"); !ok {
		t.Errorf("overlay prefix missed")
	}
}

// The story table: one judged file, the evidence around it, and the verdict
// the strongest consistent story must produce.
func verifiedSnapshot() *Snapshot {
	return &Snapshot{
		Boundary:     Boundary{Time: time.Unix(1000, 0), Kind: "host", Source: "package", Confidence: HighConfidence},
		PackageTimes: map[string]time.Time{"bash": time.Unix(500, 0), "coreutils": time.Unix(1200, 0)},
		Verify: map[string]Content{
			"/bin/bash":     {Package: "bash", Expected: testHash, Actual: testHash, State: Verified},
			"/usr/bin/edit": {Package: "bash", Expected: testHash, Actual: evilHash, State: Mismatched},
		},
	}
}

func readStory(t *testing.T, name string, snapshot *Snapshot, facts trust.Facts, authority bool) verdict {
	t.Helper()
	story := newAssessor(snapshot).read(facts, authority)
	t.Logf("%s: origin=%s why=%s evidence=%v", name, story.origin, story.why, story.evidence)
	return story
}

func TestVerdictContentVerifiedAcquitsAMovedTimestamp(t *testing.T) {
	// ctime 1200 sits after the boundary; by time alone this reads modified.
	// The ledger matches, so the story is base.
	story := readStory(t, "verified", verifiedSnapshot(), pkgFacts("/bin/bash", 1200, "bash"), false)
	if story.origin != Base {
		t.Errorf("origin = %s, want base", story.origin)
	}
	if !mentions(story.evidence, "content verified") {
		t.Errorf("evidence = %v", story.evidence)
	}
}

func TestVerdictWithoutALedgerEntryFallsBackToTime(t *testing.T) {
	// coreutils' transaction postdates the boundary, and the package's hash
	// set has no entry for /opt/new: provisioned by time, with a citation.
	story := readStory(t, "no-entry", verifiedSnapshot(), pkgFacts("/opt/new", 1300, "coreutils"), false)
	if story.origin != Provisioned {
		t.Errorf("origin = %s, want provisioned", story.origin)
	}
	if !mentions(story.evidence, "records no content hash") {
		t.Errorf("evidence = %v", story.evidence)
	}
}

func TestVerdictMismatchConvictsACleanedTimestamp(t *testing.T) {
	// ctime 900 predates the boundary; time alone acquits, content convicts.
	story := readStory(t, "mismatch", verifiedSnapshot(), pkgFacts("/usr/bin/edit", 900, "bash"), false)
	if story.origin != Modified {
		t.Errorf("origin = %s, want modified", story.origin)
	}
	if !mentions(story.evidence, "expected md5") || !mentions(story.evidence, "actual md5") {
		t.Errorf("evidence = %v", story.evidence)
	}
	if story.softened {
		t.Errorf("a non-config mismatch must not soften")
	}
}

func TestVerdictConffileMismatchSoftensExceptForAuthority(t *testing.T) {
	snapshot := verifiedSnapshot()
	snapshot.conffiles = map[string]bool{"/usr/bin/edit": true}
	story := readStory(t, "conffile", snapshot, pkgFacts("/usr/bin/edit", 900, "bash"), false)
	if !story.softened {
		t.Errorf("an edited conffile must soften the hit")
	}
	story = readStory(t, "authority", snapshot, pkgFacts("/usr/bin/edit", 900, "bash"), true)
	if story.softened {
		t.Errorf("an authority object must never soften")
	}
}

func TestVerdictTamperedLedgerFallsBackToTime(t *testing.T) {
	snapshot := verifiedSnapshot()
	snapshot.tamper = []ledgerFile{{Pkg: "bash", Stamp: time.Unix(700, 0), Path: "/info/bash.md5sums"}}
	// By time alone the file predates the boundary and reads base; the
	// mismatch is ignored because the ledger itself is suspect.
	story := readStory(t, "tampered", snapshot, pkgFacts("/usr/bin/edit", 900, "bash"), false)
	if story.origin != Base {
		t.Errorf("origin = %s, want the time-only answer", story.origin)
	}
	if !mentions(story.evidence, "changed after its last transaction") {
		t.Errorf("evidence = %v", story.evidence)
	}
}

func TestVerdictUnownedFileNamesItsTree(t *testing.T) {
	snapshot := verifiedSnapshot()
	snapshot.ownerOf = map[string]string{"/usr/lib": "libc6"}
	facts := trust.Build("/usr/lib/evil", trust.Attrs{
		Kind: trust.File, Mode: 0o755, UID: 0, Real: "/usr/lib/evil",
		CTime: 900, PackageKnown: true,
	})
	story := readStory(t, "orphan", snapshot, facts, false)
	if !mentions(story.evidence, "nearest owned ancestor /usr/lib belongs to libc6") {
		t.Errorf("evidence = %v", story.evidence)
	}
}

func TestVerdictTmpfsEvidenceWarns(t *testing.T) {
	snapshot := verifiedSnapshot()
	snapshot.Mounts = []Mount{{FSType: "tmpfs", Path: "/dev/shm", Opts: "rw"}}
	story := readStory(t, "tmpfs", snapshot, pkgFacts("/dev/shm/x", 900, "bash"), false)
	if !mentions(story.evidence, "on tmpfs at /dev/shm") {
		t.Errorf("evidence = %v", story.evidence)
	}
}

func TestVerdictReinstalledFileCountsAsRemodified(t *testing.T) {
	snapshot := &Snapshot{
		Boundary:     Boundary{Time: time.Unix(1000, 0), Kind: "host", Source: "package", Confidence: HighConfidence},
		PackageTimes: map[string]time.Time{"bash": time.Unix(500, 0)},
		Verify: map[string]Content{
			"/bin/bash": {Package: "bash", Expected: testHash, Actual: testHash, State: Verified},
		},
	}
	a := newAssessor(snapshot)
	story := a.read(pkgFacts("/bin/bash", 1200, "bash"), false)
	if story.origin != Base || a.remodified != 1 {
		t.Errorf("origin = %s remodified = %d, want base and one re-modified file", story.origin, a.remodified)
	}
	if !mentions(story.evidence, "newer than the package's last transaction") {
		t.Errorf("evidence = %v", story.evidence)
	}
}

func TestJudgeLedgerTamperedIsItsOwnFinding(t *testing.T) {
	snapshot := verifiedSnapshot()
	snapshot.tamper = []ledgerFile{
		{Pkg: "bash", Stamp: time.Unix(700, 0), Path: "/var/lib/dpkg/info/bash.md5sums"},
		{Pkg: logLedgerPkg, Stamp: time.Unix(5000, 0), Path: "/var/log/dpkg.log"},
	}
	report := Judge(snapshot, Filter{})
	classes := map[string]bool{}
	for _, finding := range report.Findings {
		classes[finding.Class] = true
		if finding.Class == "ledger-tampered" && finding.Severity != Medium {
			t.Errorf("tampered finding severity = %s", finding.Severity)
		}
	}
	if !classes["ledger-tampered"] {
		t.Fatalf("findings = %+v", report.Findings)
	}
}

func TestJudgeLedgerCoverageLines(t *testing.T) {
	snapshot := verifiedSnapshot()
	snapshot.Ledger = LedgerSummary{Kind: "none"}
	report := Judge(snapshot, Filter{})
	found := false
	for _, line := range report.Coverage {
		if strings.Contains(line, "no package content ledger") {
			found = true
		}
	}
	if !found {
		t.Errorf("coverage = %v", report.Coverage)
	}
}

func mentions(lines []string, phrase string) bool {
	for _, line := range lines {
		if strings.Contains(line, phrase) {
			return true
		}
	}
	return false
}
