package prov

import (
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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

func TestPackageLogRotationNames(t *testing.T) {
	cases := map[string]bool{
		"dpkg.log":       true,
		"dpkg.log.1":     true,
		"dpkg.log.12.gz": true,
		"dpkg.log.0":     false,
		"dpkg.log.32":    false,
		"dpkg.log.old":   false,
		"dpkg.log.1.x":   false,
		"other.log":      false,
	}
	for name, want := range cases {
		if got := packageLogRotation(name); got != want {
			t.Errorf("packageLogRotation(%q) = %t, want %t", name, got, want)
		}
	}
}

func TestReadPackageLogReadsCompressedRotations(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "dpkg.log.1")
	if err := os.WriteFile(plain, []byte("2026-11-24 22:32:00 status installed bash:amd64 5.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	compressed := filepath.Join(dir, "dpkg.log.2.gz")
	file, err := os.Create(compressed)
	if err != nil {
		t.Fatal(err)
	}
	writer := gzip.NewWriter(file)
	if _, err := writer.Write([]byte("2026-11-20 10:00:00 status installed coreutils:amd64 9.1\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	times := map[string]time.Time{}
	readPackageLog(plain, times, func() bool { return false })
	readPackageLog(compressed, times, func() bool { return false })
	if got := times["bash"]; !got.Equal(time.Date(2026, 11, 24, 22, 32, 0, 0, time.Local)) {
		t.Errorf("bash time = %v", got)
	}
	if got := times["coreutils"]; !got.Equal(time.Date(2026, 11, 20, 10, 0, 0, 0, time.Local)) {
		t.Errorf("coreutils time = %v", got)
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

func TestParseMd5sumsRowKeepsPathsWithSpaces(t *testing.T) {
	hash, path, ok := parseMd5sumsRow(testHash + "  usr/share/doc/pkg/Release Notes")
	if !ok || path != "usr/share/doc/pkg/Release Notes" {
		t.Errorf("row = %q %q %t", hash, path, ok)
	}
	if _, _, ok := parseMd5sumsRow("short usr/bin/x"); ok {
		t.Errorf("a short hash parsed as a row")
	}
}

func TestOwnershipSurvivesTheUsrmerge(t *testing.T) {
	catalog := &Catalog{kind: "dpkg", owners: map[string]Ownership{
		"/usr/bin/ls": {Name: "coreutils", Known: true},
		"/bin/ls":     {Name: "oldcore", Known: true},
	}}
	if pkg, known := catalog.Owned("/usr/bin/ls"); !known || pkg != "coreutils" {
		t.Errorf("/usr/bin/ls = %q %t", pkg, known)
	}
	if pkg, known := catalog.Owned("/bin/ls"); !known || pkg != "oldcore" {
		t.Errorf("/bin/ls = %q %t", pkg, known)
	}
	if pkg, known := catalog.Owned("/usr/bin/zz-dropped"); !known || pkg != "" {
		t.Errorf("unlisted path = %q %t, want known-empty", pkg, known)
	}
	catalog.ownerGap = "package file lists unreadable: no"
	if pkg, known := catalog.Owned("/usr/bin/ls"); known {
		t.Errorf("a failed database answered %q as owned", pkg)
	}
}

func TestDpkgTablesReadTheInfoDirectory(t *testing.T) {
	root := t.TempDir()
	info := filepath.Join(root, "info")
	if err := os.MkdirAll(info, 0o755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "bin", "ls")
	if err := os.MkdirAll(filepath.Dir(binary), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("ELF"), 0o755); err != nil {
		t.Fatal(err)
	}
	stripped := strings.TrimPrefix(binary, "/")
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(info, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("coreutils.md5sums", testHash+"  "+stripped+"\n")
	write("coreutils.list", "/bin\n"+binary+"\n")
	write("bash.conffiles", "/etc/bash.bashrc\n")
	write("bash.postinst", "#!/bin/sh\n")

	catalog := &Catalog{kind: "dpkg"}
	catalog.loadDpkgOwners(info)
	if ownership := catalog.Ownership(binary); ownership.Name != "coreutils" || !ownership.Known {
		t.Errorf("ownership = %+v", ownership)
	}
	if ownership := catalog.Ownership("/bin"); ownership.Name != "coreutils" || !ownership.Known {
		t.Errorf("directory ownership = %+v", ownership)
	}

	catalog.loadDpkgHashes(info)
	entry, ok := catalog.Hash(binary)
	if !ok || entry.Pkg != "coreutils" || entry.Hash != testHash {
		t.Errorf("hash = %+v %t", entry, ok)
	}

	catalog.loadDpkgConffiles(info)
	if !catalog.Conffile("/etc/bash.bashrc") {
		t.Errorf("/etc/bash.bashrc missed as a conffile")
	}

	catalog.loadDpkgLedgerFiles(info)
	stamped := 0
	for _, row := range catalog.ledgerFiles {
		if row.Pkg == "coreutils" {
			stamped++
		}
	}
	if stamped != 2 {
		t.Errorf("ledger stamps for coreutils = %d, want list+md5sums", stamped)
	}
}

func TestSplitInfoName(t *testing.T) {
	cases := map[string][2]string{
		"libc6:amd64.md5sums": {"libc6", "md5sums"},
		"bash.list":           {"bash", "list"},
		"bash.conffiles":      {"bash", "conffiles"},
		"bash.postinst":       {"bash", "postinst"},
	}
	for name, want := range cases {
		pkg, kind := splitInfoName(name)
		if pkg != want[0] || kind != want[1] {
			t.Errorf("splitInfoName(%q) = %q %q", name, pkg, kind)
		}
	}
}

const testHash = "d41d8cd98f00b204e9800998ecf8427e"

// writeRPMFake puts a stand-in rpm first on PATH. The scripts answer in the
// same shape as rpm 4.16, whose file-flag iterator pairs only same-sized
// arrays and whose verify exits 1 when it has deviations to report.
func writeRPMFake(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rpm")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	previous := rpmBinaryOverride
	rpmBinaryOverride = path
	t.Cleanup(func() { rpmBinaryOverride = previous })
}

func TestRPMFileListPairsFlagsWithPaths(t *testing.T) {
	writeRPMFake(t, `printf 'alpha\n1\t100644\t/etc/alpha.conf\n0\t40755\t/etc/alpha.d\n0\t100644\t/usr/bin/alpha\nbeta\n0\t100644\t/usr/lib64/libbeta.so\ngamma\ndelta\n1\t100644\t/etc/delta.conf\n'`)
	catalog := &Catalog{kind: "rpm"}
	if !catalog.Conffile("/etc/alpha.conf") {
		t.Fatal("config flag was not retained")
	}
	if ownership := catalog.Ownership("/etc/alpha.conf"); ownership.Name != "alpha" || !ownership.Known {
		t.Fatalf("conffile ownership = %+v, want alpha", ownership)
	}
	if catalog.Conffile("/usr/bin/alpha") {
		t.Fatal("a normal file was recorded as a conffile")
	}
	if ownership := catalog.Ownership("/usr/bin/alpha"); ownership.Name != "alpha" || !ownership.Known || ownership.Dir {
		t.Fatalf("alpha ownership = %+v", ownership)
	}
	if ownership := catalog.Ownership("/etc/alpha.d"); ownership.Name != "alpha" || !ownership.Dir {
		t.Fatalf("directory ownership = %+v", ownership)
	}
	if ownership := catalog.Ownership("/usr/lib64/libbeta.so"); ownership.Name != "beta" {
		t.Fatalf("beta ownership = %+v", ownership)
	}
	if count := catalog.PackageCount(); count != 4 {
		t.Fatalf("package count = %d, want 4: a package with no regular file still counts", count)
	}
}

func TestRPMVerifyKeepsOutputOnExitOne(t *testing.T) {
	writeRPMFake(t, `printf 'S.5....T.  c /etc/environment\nS.5....T.    /usr/bin/passwd\nmissing     /usr/bin/free\n'; exit 1`)
	catalog := &Catalog{kind: "rpm"}
	catalog.ensureRPMVerify()
	if catalog.rpmNote != "" {
		t.Fatalf("rpm note = %q, want no failure", catalog.rpmNote)
	}
	if !catalog.conffiles["/etc/environment"] {
		t.Fatal("a config row was not recorded")
	}
	if flags := catalog.rpmFlags["/etc/environment"]; flags != "S.5....T." {
		t.Fatalf("conffile deviation = %q, want the content flags", flags)
	}
	if flags := catalog.rpmFlags["/usr/bin/passwd"]; flags != "S.5....T." {
		t.Fatalf("passwd flags = %q", flags)
	}
	if catalog.rpmMissing != 1 {
		t.Fatalf("missing count = %d, want 1", catalog.rpmMissing)
	}
	if !catalog.RPMVerified() {
		t.Fatal("an exit-one deviation report is a completed verify")
	}
}

func TestRPMVerifyMarksACleanExitVerified(t *testing.T) {
	writeRPMFake(t, "exit 0")
	catalog := &Catalog{kind: "rpm"}
	if !catalog.RPMVerified() {
		t.Fatal("a clean rpm -Va did not count as a completed verify")
	}
}

func TestRPMVerifyAcceptsOnlyTheDeviationsExit(t *testing.T) {
	for name, body := range map[string]string{
		"exit one with no output":   "exit 1",
		"a different exit status":   `printf 'S.5....T.    /usr/bin/passwd\n'; exit 2`,
		"no output before a signal": "kill -TERM $$",
	} {
		t.Run(name, func(t *testing.T) {
			writeRPMFake(t, body)
			catalog := &Catalog{kind: "rpm"}
			catalog.ensureRPMVerify()
			if !strings.Contains(catalog.rpmNote, "failed") {
				t.Fatalf("rpm note = %q, want the failure line", catalog.rpmNote)
			}
			if len(catalog.rpmFlags) != 0 {
				t.Fatalf("flags = %v, want no content evidence", catalog.rpmFlags)
			}
			if catalog.RPMVerified() {
				t.Fatal("a failed verify was accepted as complete")
			}
		})
	}
}

func TestDpkgPackageCountCountsEmptyLists(t *testing.T) {
	info := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(info, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("coreutils.list", "/usr/bin/ls\n")
	write("basesystem.list", "")
	catalog := &Catalog{kind: "dpkg"}
	catalog.loadDpkgOwners(info)
	if count := catalog.PackageCount(); count != 2 {
		t.Fatalf("package count = %d, want 2 (an empty file list is still a package)", count)
	}
}

// TestInterruptedLoadAnswersUnknownOwnership pins the interrupted-catalog
// contract: a table cut at the interrupt answers unknown ownership for paths
// it never reached, so a partial report cannot mint false unowned findings.
func TestInterruptedLoadAnswersUnknownOwnership(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.list"), []byte("/usr/bin/a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	catalog := &Catalog{kind: "dpkg", ctx: ctx}
	catalog.loadDpkgOwners(dir)
	if !catalog.truncated {
		t.Fatal("the cut load is not marked")
	}
	if ownership := catalog.Ownership("/usr/bin/zzz"); ownership.Known {
		t.Fatalf("a cut catalog answered %+v, want unknown", ownership)
	}
	if !strings.Contains(strings.Join(catalog.Gaps(), "\n"), "stopped at the interrupt") {
		t.Fatalf("gaps = %v, want the truncation line", catalog.Gaps())
	}
}

// TestTruncatedRowReadAnswersUnknownOwnership pins the read-error contract: a
// table that dies mid-file (an oversized row, an I/O error) is a truncated
// table — the gap states it and ownership answers unknown, never unowned.
func TestTruncatedRowReadAnswersUnknownOwnership(t *testing.T) {
	dir := t.TempDir()
	long := "/" + strings.Repeat("x", 1<<20+16) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "a.list"), []byte("/usr/bin/a\n"+long), 0o644); err != nil {
		t.Fatal(err)
	}
	catalog := &Catalog{kind: "dpkg"}
	catalog.loadDpkgOwners(dir)
	if ownership := catalog.Ownership("/usr/bin/zzz"); ownership.Known {
		t.Fatalf("a table that died mid-file answered %+v, want unknown", ownership)
	}
	gaps := strings.Join(catalog.Gaps(), "\n")
	if !strings.Contains(gaps, "package file lists unreadable") || !strings.Contains(gaps, "stopped at a read error") {
		t.Fatalf("gaps = %q", gaps)
	}
}

// A conffile table that cannot be read states its gap and cuts the catalog
// with the rest, instead of answering an empty set as if it were complete.
func TestConffileReadErrorStatesTheGap(t *testing.T) {
	catalog := &Catalog{kind: "dpkg"}
	catalog.loadDpkgConffiles(filepath.Join(t.TempDir(), "absent"))
	if catalog.conffileGap == "" || !catalog.truncated {
		t.Fatalf("gap = %q truncated = %t, want a stated gap and the cut", catalog.conffileGap, catalog.truncated)
	}
	if gaps := catalog.Gaps(); !strings.Contains(strings.Join(gaps, "\n"), "package conffile records unreadable") {
		t.Fatalf("gaps = %v", gaps)
	}
}

func TestReadPackageLogStatesReadErrors(t *testing.T) {
	if err := readPackageLog(filepath.Join(t.TempDir(), "absent"), map[string]time.Time{}, func() bool { return false }); err == nil {
		t.Fatal("a missing transaction log read as success")
	}
}

func TestRPMTableFailureAnswersUnknownOwnership(t *testing.T) {
	writeRPMFake(t, "exit 1")
	catalog := &Catalog{kind: "rpm"}
	catalog.loadRPMOwners()
	if ownership := catalog.Ownership("/usr/bin/zzz"); ownership.Known {
		t.Fatalf("a failed rpm -qa answered %+v, want unknown", ownership)
	}
	if !strings.Contains(strings.Join(catalog.Gaps(), "\n"), "rpm file lists unreadable") {
		t.Fatalf("gaps = %v", catalog.Gaps())
	}
}
