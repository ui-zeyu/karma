package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"karma/internal/prov"
	"karma/internal/trust"
)

const (
	testHash = "d41d8cd98f00b204e9800998ecf8427e"
	evilHash = "0123456789abcdef0123456789abcdef"
)

func TestDPKGExpectedIsEmptyWithoutJudgedFiles(t *testing.T) {
	hashes := map[string]prov.HashEntry{
		"usr/bin/bash": {Pkg: "bash", Hash: testHash},
		"etc/passwd":   {Pkg: "passwd", Hash: testHash},
	}
	expected := dpkgExpected(hashes, map[string]trust.Facts{
		"/etc": {Path: "/etc", Real: "/etc", Kind: trust.Dir},
	})
	if len(expected) != 0 {
		t.Fatalf("expected rows = %+v, want an empty ledger", expected)
	}
	expected = dpkgExpected(hashes, map[string]trust.Facts{
		"/bin/bash": {Path: "/bin/bash", Real: "/usr/bin/bash", Kind: trust.File},
	})
	if len(expected) != 1 || expected["usr/bin/bash"].pkg != "bash" {
		t.Errorf("expected rows = %+v, want the judged bash file", expected)
	}
}

func pkgFacts(path string, ctime int64, pkg string) trust.Facts {
	return trust.Build(path, trust.Attrs{
		Kind: trust.File, Mode: 0o755, UID: 0, Real: path, CTime: ctime,
		Package: pkg, PackageKnown: true,
	})
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

func TestHashFilesAndJoinContent(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
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
	expected := map[string]ledgerEntry{
		stripped: {pkg: "coreutils", hash: hash},
	}
	actual := hashFiles(t.Context(), map[string]trust.Facts{
		binary: pkgFacts(binary, 900, "coreutils"),
	}, expected)
	if actual[binary] != hash {
		t.Errorf("hashFiles = %v", actual)
	}
	verify := joinContent(actual, expected)
	if content := verify[binary]; content.State != Verified || content.Package != "coreutils" {
		t.Errorf("content = %+v, want verified against coreutils", content)
	}
}

func TestLedgerPackagesCountsDistinctJudgedPackages(t *testing.T) {
	expected := map[string]ledgerEntry{
		"usr/bin/a": {pkg: "coreutils", hash: testHash},
		"usr/bin/b": {pkg: "coreutils", hash: evilHash},
		"usr/bin/c": {pkg: "bash", hash: testHash},
	}
	if got := ledgerPackages(expected); got != 2 {
		t.Fatalf("ledger packages = %d, want 2", got)
	}
}

func TestLedgerSummaryKeepsTheRPMInventoryCount(t *testing.T) {
	snapshot := &Snapshot{}
	snapshot.attachEvidence(evidenceSet{kind: "rpm", packages: 195})
	if snapshot.Ledger.Packages != 195 {
		t.Fatalf("packages = %d, want the rpm inventory count", snapshot.Ledger.Packages)
	}
	if snapshot.Ledger.Entries != 0 {
		t.Fatalf("entries = %d, want 0 when no judged file reached rpm -Va", snapshot.Ledger.Entries)
	}
}

func TestLedgerSummaryCountsTheRPMVerify(t *testing.T) {
	path := "/usr/bin/tool"
	snapshot := &Snapshot{Objects: map[string]trust.Facts{
		path: pkgFacts(path, 900, "tools"),
	}}
	snapshot.attachEvidence(evidenceSet{
		kind: "rpm", packages: 1, rpmVerified: true, objects: snapshot.Objects,
		rpmFlag: map[string]string{"/usr/bin/deviation": "S.5....T."},
	})
	if snapshot.Ledger.Entries != 1 || snapshot.Ledger.Verified != 1 || snapshot.Ledger.Mismatched != 0 {
		t.Fatalf("ledger = %+v, want one checked and verified file", snapshot.Ledger)
	}
	content, ok := snapshot.Verify[path]
	if !ok || content.State != Verified || content.Method != methodRPM {
		t.Fatalf("content = %+v %t, want rpm verified", content, ok)
	}
}

func TestRPMDeviationFollowsTheResolvedSpelling(t *testing.T) {
	facts := pkgFacts("/bin/bash", 900, "bash")
	facts.Real = "/usr/bin/bash"
	snapshot := &Snapshot{Objects: map[string]trust.Facts{"/bin/bash": facts}}
	snapshot.attachEvidence(evidenceSet{
		kind: "rpm", packages: 1, objects: snapshot.Objects,
		rpmFlag: map[string]string{"/usr/bin/bash": "S.5....T."},
	})
	if content := snapshot.Verify["/usr/bin/bash"]; content.State != Mismatched || content.Method != methodRPM {
		t.Fatalf("resolved content = %+v, want the rpm mismatch under the real path", content)
	}
}

func TestRPMConffileDeviationSoftens(t *testing.T) {
	path := "/etc/environment"
	facts := pkgFacts(path, 900, "setup")
	snapshot := &Snapshot{Objects: map[string]trust.Facts{path: facts}}
	snapshot.attachEvidence(evidenceSet{
		kind: "rpm", packages: 1, objects: snapshot.Objects,
		conffiles: map[string]bool{path: true},
		rpmFlag:   map[string]string{path: "S.5....T."},
	})
	content := snapshot.Verify[path]
	if content.State != Mismatched || content.Method != methodRPM {
		t.Fatalf("content = %+v, want an rpm mismatch", content)
	}
	story := newAssessor(snapshot).read(facts, false)
	if story.origin != Modified || !story.softened {
		t.Fatalf("story = %+v, want modified and softened", story)
	}
	if !mentions(story.evidence, "rpm -Va reports a deviation") {
		t.Errorf("evidence = %v", story.evidence)
	}
}

func TestHashFilesKeepsTheResolvedSpelling(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "bin", "ls")
	if err := os.MkdirAll(filepath.Dir(binary), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("ELF"), 0o755); err != nil {
		t.Fatal(err)
	}
	hash, ok := hashFile(binary)
	if !ok {
		t.Fatal("hashFile failed")
	}
	stripped := strings.TrimPrefix(binary, "/")
	facts := pkgFacts("/bin/ls", 900, "coreutils")
	facts.Real = binary
	actual := hashFiles(t.Context(), map[string]trust.Facts{"/bin/ls": facts},
		map[string]ledgerEntry{stripped: {pkg: "coreutils", hash: hash}})
	if len(actual) != 1 || actual[binary] != hash {
		t.Fatalf("actual = %v, want one resolved key", actual)
	}
	if _, alias := actual["/bin/ls"]; alias {
		t.Fatal("hashFiles kept a second spelling for the same file")
	}
}

func TestLedgerTamperReadsTheArtifactEdge(t *testing.T) {
	// The container became the artifact at epoch 1000. bash came with the
	// image (last transaction 500); coreutils was installed after the container
	// started (1500). An image build's uniform stamp at 900 sits past bash's
	// transaction but before the edge, so it is the artifact, not tampering.
	// The 1001 write is the smallest rewrite the model must catch: one second
	// past the edge, no statistical margin. The log row is dated by its own
	// newest entry, so the write at 1500 passes and the rewrite at 1600 does not.
	edge := Boundary{Time: time.Unix(1000, 0), Kind: "container", Source: "pid1", Confidence: HighConfidence}
	times := map[string]time.Time{
		"bash":      time.Unix(500, 0),
		"coreutils": time.Unix(1500, 0),
	}
	rows := []ledgerFile{
		{Pkg: "bash", Stamp: time.Unix(400, 0), Path: "/i/transaction"},
		{Pkg: "bash", Stamp: time.Unix(900, 0), Path: "/i/image-build"},
		{Pkg: "bash", Stamp: time.Unix(1001, 0), Path: "/i/tamper"},
		{Pkg: "coreutils", Stamp: time.Unix(1500, 0), Path: "/i/install"},
		{Pkg: logLedgerPkg, Stamp: time.Unix(1500, 0), Path: prov.PackageLog},
		{Pkg: logLedgerPkg, Stamp: time.Unix(1600, 0), Path: prov.PackageLog},
	}
	got := ledgerTamper(edge, times, rows)
	if len(got) != 2 || got[0].Path != "/i/tamper" || got[1].Stamp.Unix() != 1600 {
		t.Errorf("tampered = %+v, want the 1001 ledger write and the 1600 log rewrite", got)
	}

	// A package with no recorded transaction cannot be timed against one; a
	// write past the edge is still outside package management.
	got = ledgerTamper(edge, times, []ledgerFile{{Pkg: "unknown", Stamp: time.Unix(1200, 0), Path: "/i/7"}})
	if len(got) != 1 {
		t.Errorf("unrecorded package = %+v, want the post-edge write", got)
	}

	// Without an artifact edge there is nothing to date the write against.
	if got := ledgerTamper(Boundary{}, times, rows); got != nil {
		t.Errorf("tamper without a boundary = %+v", got)
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
	snapshot.Objects = map[string]trust.Facts{"/usr/lib": pkgFacts("/usr/lib", 0, "libc6")}
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
	a.read(pkgFacts("/bin/bash", 1200, "bash"), false)
	if story.origin != Base || len(a.remodifiedSet) != 1 {
		t.Errorf("origin = %s remodified = %d, want base and one re-modified file", story.origin, len(a.remodifiedSet))
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
