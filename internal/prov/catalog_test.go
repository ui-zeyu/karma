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
