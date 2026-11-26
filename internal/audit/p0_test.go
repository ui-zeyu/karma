package audit

import (
	"testing"
	"time"
)

func TestProcessReachUsesEffectiveUID(t *testing.T) {
	// A setuid-root image keeps the caller's real uid and runs as root.
	process := Process{UID: 1000, EUID: 0}
	if got := processReach(process); got != RootAsset {
		t.Fatalf("reach = %s, want root", got)
	}
	process = Process{UID: 0, EUID: 1000}
	if got := processReach(process); got != UserAsset {
		t.Fatalf("reach = %s, want user", got)
	}
}

func TestJudgePackagesIgnoresFilesOlderThanTheBoundary(t *testing.T) {
	boundary := time.Unix(200, 0)
	transaction := time.Unix(100, 0)
	snapshot := &Snapshot{
		Boundary: Boundary{Time: boundary, Kind: "container", Source: "pid1", Confidence: HighConfidence},
		Packages: PackageState{
			Kind: "dpkg",
			Anomalies: []PackageFile{
				{Path: "/usr/bin/old", Package: "old", CTime: 150, Transaction: transaction},
				{Path: "/usr/bin/new", Package: "new", CTime: 250, Transaction: transaction},
			},
		},
	}
	report := Judge(snapshot, Filter{})
	var paths []string
	for _, finding := range report.Findings {
		if finding.Class == "package-file-modified" {
			paths = append(paths, finding.Path)
		}
	}
	if len(paths) != 1 || paths[0] != "/usr/bin/new" {
		t.Fatalf("package findings = %v, want only /usr/bin/new", paths)
	}
}

func TestSetBoundaryRetargetsTheLedgerSummary(t *testing.T) {
	snapshot := &Snapshot{
		Boundary: Boundary{Time: time.Unix(300, 0), Confidence: HighConfidence},
		PackageTimes: map[string]time.Time{
			"pkg": time.Unix(100, 0),
		},
		ledgerRows: []ledgerFile{
			{Pkg: "pkg", Stamp: time.Unix(200, 0), Path: "/var/lib/dpkg/info/pkg.list"},
		},
	}
	snapshot.tamper = ledgerTamper(snapshot.Boundary, snapshot.PackageTimes, snapshot.ledgerRows)
	snapshot.Ledger.Tampered = tamperedPackages(snapshot.tamper)
	if len(snapshot.Ledger.Tampered) != 0 {
		t.Fatalf("tampered before retarget = %v", snapshot.Ledger.Tampered)
	}
	snapshot.SetBoundary(Boundary{Time: time.Unix(150, 0), Confidence: HighConfidence})
	if len(snapshot.Ledger.Tampered) != 1 || snapshot.Ledger.Tampered[0] != "pkg" {
		t.Fatalf("tampered after retarget = %v, want [pkg]", snapshot.Ledger.Tampered)
	}
}
