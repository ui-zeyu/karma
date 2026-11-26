package audit

// The content ledger: what the distribution says it shipped, compared against
// what the disk carries. dpkg keeps a per-file md5 beside every package's
// list; rpm answers a whole-system verify through rpm -Va. A mismatch convicts
// a file whose timestamps were cleaned, and a match acquits one whose
// timestamps a package upgrade moved — the two evidence lines that time alone
// cannot give.

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"karma/internal/prov"
	"karma/internal/trust"
)

// VerifyState is what a ledger comparison answered.
type VerifyState uint8

const (
	Unverified VerifyState = iota // no ledger entry, or the bytes could not be read
	Verified                      // the content matches the ledger
	Mismatched                    // the content differs from the ledger
)

// Content is one path's ledger comparison: the package that claims the file,
// the hash the ledger records, the hash the disk carries.
type Content struct {
	Package  string
	Expected string
	Actual   string
	State    VerifyState
}

// Mount is one mounted filesystem: context for where evidence lives.
type Mount struct {
	FSType string `json:"fstype"`
	Path   string `json:"path"`
	Opts   string `json:"opts"`
}

// LedgerSummary says which content ledger the run used and how far it reached.
type LedgerSummary struct {
	Kind     string   `json:"kind"`               // dpkg, rpm, none
	Packages int      `json:"packages"`           // packages whose content hashes were compared
	Entries  int      `json:"entries"`            // ledger hash entries read for those packages
	Verified int      `json:"verified"`           // judged files whose content matched the ledger
	Tampered []string `json:"tampered,omitempty"` // packages whose ledger files changed after their last transaction
	Note     string   `json:"note,omitempty"`     // a degraded answer worth a coverage line
}

// logLedgerPkg marks the transaction log's own row in the ledger's file set:
// it belongs to no package, and a rewrite of it moves the artifact edge.
const logLedgerPkg = prov.LogPackage

// ledgerFile is one package metadata file the catalog carried.
type ledgerFile = prov.LedgerFile

// ledgerEntry is the hash one package's ledger records for one path.
type ledgerEntry struct {
	pkg  string
	hash string
}

// mountTable answers a path's filesystem by longest prefix.
type mountTable []Mount

func buildMountTable(mounts []Mount) mountTable {
	sorted := append([]Mount(nil), mounts...)
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i].Path) > len(sorted[j].Path) })
	return sorted
}

func (t mountTable) mount(path string) (Mount, bool) {
	for _, mount := range t {
		// The root mount backs every path; trust.Under asks on a path
		// boundary and never answers for "/", so it is asked directly.
		if mount.Path == "/" || trust.Under(path, mount.Path) {
			return mount, true
		}
	}
	return Mount{}, false
}

// volatileMount reports a filesystem whose contents die with the boot: a
// finding there is evidence the operator has to capture now.
func volatileMount(mount Mount) bool { return mount.FSType == "tmpfs" }

// parseMountsLine reads one /proc/self/mounts row: `devspec mountpoint fstype opts`.
func parseMountsLine(line string) (Mount, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return Mount{}, false
	}
	return Mount{FSType: fields[2], Path: fields[1], Opts: fields[3]}, true
}

func readMounts() []Mount {
	data, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return nil
	}
	var mounts []Mount
	for _, line := range strings.Split(string(data), "\n") {
		if mount, ok := parseMountsLine(line); ok {
			mounts = append(mounts, mount)
		}
	}
	return mounts
}

const hashSizeCap = 128 << 20

func hashFile(path string) (string, bool) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > hashSizeCap {
		return "", false
	}
	file, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer file.Close()
	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", false
	}
	return hex.EncodeToString(hash.Sum(nil)), true
}

func hashFiles(ctx context.Context, objects map[string]trust.Facts, expected map[string]ledgerEntry) map[string]string {
	actual := map[string]string{}
	for _, facts := range objects {
		if ctx.Err() != nil {
			break
		}
		if facts.Kind != trust.File || facts.Real == "" || !ledgerCandidate(facts, expected) {
			continue
		}
		hash, ok := hashFile(facts.Real)
		if !ok {
			continue
		}
		actual[facts.Real] = hash
		if facts.Path != facts.Real {
			actual[facts.Path] = hash
		}
	}
	return actual
}

// ledgerCandidate reports whether the ledger records a hash under either
// spelling of the file.
func ledgerCandidate(facts trust.Facts, expected map[string]ledgerEntry) bool {
	if len(expected) == 0 {
		return false
	}
	for _, key := range usrKeys(facts.Real) {
		if _, ok := expected[key]; ok {
			return true
		}
	}
	if facts.Path != facts.Real {
		for _, key := range usrKeys(facts.Path) {
			if _, ok := expected[key]; ok {
				return true
			}
		}
	}
	return false
}

// joinContent pairs each actual hash with the ledger entry recorded for the
// same file, under any spelling the ledger may have used.
func joinContent(actual map[string]string, expected map[string]ledgerEntry) map[string]Content {
	verify := map[string]Content{}
	for path, hash := range actual {
		content := Content{Actual: hash, State: Unverified}
		for _, key := range usrKeys(path) {
			if entry, hit := expected[key]; hit {
				content.Package = entry.pkg
				content.Expected = entry.hash
				if content.Expected == hash {
					content.State = Verified
				} else {
					content.State = Mismatched
				}
				break
			}
		}
		verify[path] = content
	}
	return verify
}

// overlayRpm folds rpm -Va's whole-system verify into the content table. rpm
// carries no per-file digest, so a flagged row is a mismatch with no expected
// hash to quote; the assessor cites the flag word instead.
func overlayRpm(verify map[string]Content, flags map[string]string) {
	if len(flags) == 0 {
		return
	}
	for path, flag := range flags {
		content := verify[path]
		if content.State == Verified {
			// A hash match outranks rpm's own flag: the file may have moved
			// without its content changing.
			continue
		}
		content.State = Mismatched
		content.Actual = "rpm -Va " + flag
		verify[path] = content
	}
}

// evidenceSet is everything the ledger pass gathered; attachEvidence turns it
// into the snapshot fields the judge reads.
type evidenceSet struct {
	actual    map[string]string
	expected  map[string]ledgerEntry
	conffiles map[string]bool
	rows      []ledgerFile
	mounts    []Mount
	rpmFlag   map[string]string
	kind      string
	note      string
}

// attachEvidence joins the collected hashes with the ledger, dates the
// packages, and records the tamper verdict.
func (s *Snapshot) attachEvidence(evidence evidenceSet) {
	s.Verify = joinContent(evidence.actual, evidence.expected)
	overlayRpm(s.Verify, evidence.rpmFlag)
	s.Mounts = evidence.mounts
	s.conffiles = evidence.conffiles
	s.ledgerRows = evidence.rows
	s.tamper = ledgerTamper(s.Boundary, s.PackageTimes, s.ledgerRows)
	verified := 0
	packages := map[string]bool{}
	for _, entry := range evidence.expected {
		packages[entry.pkg] = true
	}
	for _, content := range s.Verify {
		if content.State == Verified {
			verified++
		}
	}
	s.Ledger = LedgerSummary{
		Kind:     evidence.kind,
		Packages: len(packages),
		Entries:  len(evidence.expected),
		Verified: verified,
		Tampered: tamperedPackages(s.tamper),
		Note:     evidence.note,
	}
}

// tamperedPackages names the packages whose ledger files moved, one name per
// package. It is derived rather than stored so a later --since retarget and
// the printed summary cannot disagree.
func tamperedPackages(rows []ledgerFile) []string {
	var tampered []string
	seen := map[string]bool{}
	for _, row := range rows {
		if row.Pkg == logLedgerPkg || seen[row.Pkg] {
			continue
		}
		seen[row.Pkg] = true
		tampered = append(tampered, row.Pkg)
	}
	return tampered
}

// ledgerTamper answers which ledger files were written outside package
// management: after the artifact edge and after the package's own last
// transaction. dpkg writes its ledger files during a transaction and closes
// the transaction's log entry afterwards, so a ledger stamp later than both is
// a writer the package manager did not make. The artifact edge keeps a
// container image's own build — every file extracted at once, long after the
// packaged transaction — from reading as tampering, and it needs no statistical
// margin: a rewrite one minute past the edge convicts the same as one a week
// past it.
func ledgerTamper(boundary Boundary, times map[string]time.Time, rows []ledgerFile) []ledgerFile {
	if boundary.Time.IsZero() {
		return nil
	}
	latest := latestPackageTime(times)
	var out []ledgerFile
	for _, row := range rows {
		if !row.Stamp.After(boundary.Time) {
			continue
		}
		if row.Pkg == logLedgerPkg {
			// The log is dated by its own content, not by a package: a write
			// past the newest entry is the rewrite this row exists to catch.
			if !row.Stamp.After(latest) {
				continue
			}
			out = append(out, row)
			continue
		}
		if stamp, ok := times[row.Pkg]; ok && !row.Stamp.After(stamp) {
			continue
		}
		out = append(out, row)
	}
	return out
}

// candidatePackages names the packages the snapshot judged: the ledger is read
// for those, so a host with thousands of packages costs only its evidence.
func candidatePackages(objects map[string]trust.Facts) map[string]bool {
	packages := map[string]bool{}
	for _, facts := range objects {
		if facts.PackageKnown && facts.Package != "" {
			packages[facts.Package] = true
		}
	}
	return packages
}

// usrKeys is a path's ledger spellings: dpkg hashes files relative to / and
// records the spelling it installed, which on a usrmerge host may be the
// /usr-less one.
func usrKeys(path string) []string {
	trimmed := strings.TrimPrefix(path, "/")
	keys := []string{trimmed}
	if rest, ok := strings.CutPrefix(trimmed, "usr/"); ok {
		keys = append(keys, rest)
	}
	return keys
}

// shortHash clips a hash for an evidence line: the operator reads enough to
// compare by eye, never the whole digest.
func shortHash(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}
