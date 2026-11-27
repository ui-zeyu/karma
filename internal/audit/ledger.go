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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"karma/internal/localfs"
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

// String names a verify state in the report's JSON vocabulary.
func (s VerifyState) String() string {
	switch s {
	case Verified:
		return "verified"
	case Mismatched:
		return "mismatched"
	}
	return "unverified"
}

// MarshalJSON keeps the verify state a word, like every other enum the JSON
// answer carries.
func (s VerifyState) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

const (
	methodMD5 = "md5"
	methodRPM = "rpm -Va"
)

// Content is one path's ledger comparison: the package that claims the file,
// the hash the ledger records, the hash the disk carries.
type Content struct {
	Package  string      `json:"package,omitempty"`
	Expected string      `json:"expected,omitempty"`
	Actual   string      `json:"actual,omitempty"`
	State    VerifyState `json:"state"`
	Method   string      `json:"method,omitempty"`
}

// Mount is one mounted filesystem: context for where evidence lives.
type Mount struct {
	FSType string `json:"fstype"`
	Path   string `json:"path"`
	Opts   string `json:"opts"`
}

// LedgerSummary says which content ledger the run used and how far it reached.
type LedgerSummary struct {
	Kind       string   `json:"kind"`                 // dpkg, rpm, none
	Packages   int      `json:"packages"`             // packages the ledger covered
	Entries    int      `json:"entries"`              // hash entries read, or files rpm checked
	Verified   int      `json:"verified"`             // judged files whose content matched the ledger
	Mismatched int      `json:"mismatched,omitempty"` // judged files whose content deviated
	Tampered   []string `json:"tampered,omitempty"`   // packages whose ledger files changed after their last transaction
	Note       string   `json:"note,omitempty"`       // a degraded answer worth a coverage line
}

// logLedgerPkg marks the transaction log's own row in the ledger's file set:
// it belongs to no package, and a rewrite of it moves the artifact edge.
const logLedgerPkg = prov.LogPackage

// ledgerFile is one package metadata file the catalog carried.
type ledgerFile = prov.LedgerFile

// ledgerLookup is the one ledger row probe: the catalog answers it under
// every spelling it indexes (usrmerge pairs included). The batch pass and
// the graph's late discoveries both call it, so a file cannot verify one way
// in the report and the other way in a graph.
type ledgerLookup func(path string) (prov.HashEntry, bool)

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

// hashFile reads and md5s one regular file. The second answer names why the
// comparison could not run — an unreadable file, or one past the size cap —
// and is empty on success, so the caller can state the failure instead of
// reporting the file as unrecorded.
func hashFile(path string) (string, string) {
	file, err := localfs.Open(path)
	if err != nil {
		return "", "unreadable: " + err.Error()
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", "unreadable: " + err.Error()
	}
	if info.Size() > hashSizeCap {
		return "", fmt.Sprintf("larger than the %dMiB comparison cap", hashSizeCap>>20)
	}
	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", "read stopped: " + err.Error()
	}
	return hex.EncodeToString(hash.Sum(nil)), ""
}

// hashFiles hashes the judged files the ledger records. The second answer
// maps the files whose comparison could not run to the reason, so the
// assessor can name the failure — the ledger rows for them exist.
func hashFiles(ctx context.Context, objects map[string]trust.Facts, lookup ledgerLookup) (map[string]string, map[string]string) {
	seen := map[string]bool{}
	var paths []string
	for _, facts := range objects {
		if facts.Kind != trust.File || facts.Real == "" || seen[facts.Real] || !ledgerCandidate(facts, lookup) {
			continue
		}
		// The object map carries both the asked and the resolved spelling; one
		// hash of the resolved inode answers both.
		seen[facts.Real] = true
		paths = append(paths, facts.Real)
	}
	actual := map[string]string{}
	failed := map[string]string{}
	if len(paths) == 0 {
		return actual, failed
	}
	reasons := make([]string, len(paths))
	each(ctx, len(paths), workerCount(1), func(_, i int) {
		hash, reason := hashFile(paths[i])
		if hash != "" {
			actual[paths[i]] = hash
		} else {
			reasons[i] = reason
		}
	})
	for index, reason := range reasons {
		if reason != "" {
			failed[paths[index]] = reason
		}
	}
	return actual, failed
}

// ledgerCandidate reports whether the ledger records a hash under either
// spelling of the file.
func ledgerCandidate(facts trust.Facts, lookup ledgerLookup) bool {
	if lookup == nil {
		return false
	}
	for _, key := range usrKeys(facts.Real) {
		if _, ok := lookup(key); ok {
			return true
		}
	}
	if facts.Path != facts.Real {
		for _, key := range usrKeys(facts.Path) {
			if _, ok := lookup(key); ok {
				return true
			}
		}
	}
	return false
}

// evidenceSet is everything the ledger pass gathered; attachEvidence turns it
// into the snapshot fields the judge reads.
type evidenceSet struct {
	actual map[string]string
	// failed names the judged files whose comparison could not run, with the
	// reason; the ledger rows for them exist.
	failed      map[string]string
	lookup      ledgerLookup
	conffiles   map[string]bool
	rows        []ledgerFile
	mounts      []Mount
	rpmFlag     map[string]string
	rpmVerified bool
	objects     map[string]trust.Facts
	kind        string
	note        string
	// packages is how many packages the ledger covered. dpkg counts the
	// packages among the judged hash entries; rpm's ledger is a whole-system
	// verify, so it counts every installed package.
	packages int
}

// ledgerAnswer is the bulk state one content verdict reads: which ledger
// answered, and rpm's verify flags when rpm is the ledger.
type ledgerAnswer struct {
	kind     string
	flags    map[string]string
	verified bool
}

func (s *Snapshot) answer() ledgerAnswer {
	ans := ledgerAnswer{kind: s.Ledger.Kind}
	if ans.kind == "rpm" {
		ans.flags = s.catalog.RPMFlags()
		ans.verified = s.catalog.RPMVerified()
	}
	return ans
}

// contentAnswer is the one content verdict the ledger gives a judged file.
// It is the single source for both the batch pass and the graph's late
// discoveries, so a file cannot verify one way in the report and the other
// way in a graph. actual is the file's md5 when the caller has one (the dpkg
// batch hashes in parallel); rpm verifies by its own flag list and ignores
// it. An empty actual answers no dpkg verdict: the caller states separately
// whether the ledger lacked the row or the read failed. ok answers whether
// the ledger had a verdict at all — without one the assessor falls back to
// time.
func contentAnswer(ans ledgerAnswer, lookup ledgerLookup, facts trust.Facts, actual string) (Content, bool) {
	switch ans.kind {
	case "dpkg":
		entry, ok := lookup(facts.Real)
		if !ok && facts.Path != facts.Real {
			entry, ok = lookup(facts.Path)
		}
		if !ok || actual == "" {
			return Content{}, false
		}
		content := Content{Package: entry.Pkg, Expected: entry.Hash, Actual: actual, Method: methodMD5}
		if actual == entry.Hash {
			content.State = Verified
		} else {
			content.State = Mismatched
		}
		return content, true
	case "rpm":
		// A deviation row is direct evidence even when the verify never ran
		// to its end, and it names directories as well as files; only the
		// positive verdict needs a completed verify and a regular file.
		if flag, ok := ans.flags[facts.Real]; ok {
			return Content{Package: facts.Package, State: Mismatched, Method: methodRPM, Actual: "rpm -Va " + flag}, true
		}
		if flag, ok := ans.flags[facts.Path]; ok {
			return Content{Package: facts.Package, State: Mismatched, Method: methodRPM, Actual: "rpm -Va " + flag}, true
		}
		if !ans.verified || facts.Kind != trust.File {
			return Content{}, false
		}
		if facts.PackageKnown && facts.Package != "" {
			return Content{Package: facts.Package, State: Verified, Method: methodRPM}, true
		}
	}
	return Content{}, false
}

// attachEvidence answers every judged file through the one content verdict,
// dates the packages, and records the tamper verdict.
func (s *Snapshot) attachEvidence(evidence evidenceSet) {
	ans := ledgerAnswer{kind: evidence.kind, flags: evidence.rpmFlag, verified: evidence.rpmVerified}
	s.Verify = map[string]Content{}
	for _, facts := range evidence.objects {
		// The rpm flags branch names directories too; the dpkg branch only
		// answers files, and its hash pass already filtered the candidates.
		if facts.Real == "" {
			continue
		}
		hash := evidence.actual[facts.Real]
		if content, ok := contentAnswer(ans, evidence.lookup, facts, hash); ok {
			s.Verify[facts.Real] = content
		}
	}
	s.Mounts = evidence.mounts
	s.conffiles = evidence.conffiles
	s.ledgerRows = evidence.rows
	s.tamper = ledgerTamper(s.Boundary, s.PackageTimes, s.ledgerRows)
	// The unreadable set is the snapshot's one map, so files the graph
	// discovers later join the same answer the assessor reads.
	if s.unhashable == nil {
		s.unhashable = map[string]string{}
	}
	for path, reason := range evidence.failed {
		s.unhashable[path] = reason
	}
	verified, mismatched := 0, 0
	for _, content := range s.Verify {
		switch content.State {
		case Verified:
			verified++
		case Mismatched:
			mismatched++
		}
	}
	packages := evidence.packages
	entries := len(s.Verify)
	if evidence.kind == "dpkg" {
		entries, packages = judgedLedgerRows(evidence.lookup, evidence.objects)
	}
	s.Ledger = LedgerSummary{
		Kind:       evidence.kind,
		Packages:   packages,
		Entries:    entries,
		Verified:   verified,
		Mismatched: mismatched,
		Tampered:   tamperedPackages(s.tamper),
		Note:       evidence.note,
	}
	s.ledgerReady = true
}

// judgedLedgerRows counts the ledger rows the judged set can compare against
// and the packages they belong to. It probes the catalog's index directly —
// the whole-database scan the old prebuilt expected map needed is gone.
func judgedLedgerRows(lookup ledgerLookup, objects map[string]trust.Facts) (entries, packages int) {
	keys := map[string]bool{}
	for _, facts := range objects {
		if facts.Kind != trust.File {
			continue
		}
		for _, path := range []string{facts.Path, facts.Real} {
			for _, key := range usrKeys(path) {
				keys[key] = true
			}
		}
	}
	owners := map[string]bool{}
	for key := range keys {
		if entry, ok := lookup(key); ok {
			owners[entry.Pkg] = true
			entries++
		}
	}
	return entries, len(owners)
}

// ensureContent fills the ledger's answer for paths discovered after the
// collection pass, such as the files an object graph walks to. The catalog
// already holds the hash index and the rpm verify result, so the read is one
// lookup and one hash per discovered file.
func (s *Snapshot) ensureContent(paths []string) {
	if s == nil || !s.ledgerReady || s.catalog == nil || len(paths) == 0 {
		return
	}
	if s.Verify == nil {
		s.Verify = map[string]Content{}
	}
	ans := s.answer()
	for _, path := range paths {
		facts := s.Facts(path)
		if facts.Kind != trust.File || facts.Real == "" {
			continue
		}
		if _, seen := s.Verify[facts.Real]; seen {
			continue
		}
		// A late discovery costs one lookup and one hash; the rpm ledger
		// answers from its flags without a read.
		hash := ""
		if ans.kind == "dpkg" {
			_, known := s.catalog.Hash(facts.Real)
			if !known && facts.Path != facts.Real {
				_, known = s.catalog.Hash(facts.Path)
			}
			if !known {
				continue
			}
			var reason string
			hash, reason = hashFile(facts.Real)
			if hash == "" {
				s.noteUnhashable(facts.Real, reason)
				continue
			}
		}
		if content, ok := contentAnswer(ans, s.catalog.Hash, facts, hash); ok {
			s.Verify[facts.Real] = content
		}
	}
}

// noteUnhashable records one judged file whose content comparison could not
// run, so the assessor states the failure instead of blaming a missing
// ledger row.
func (s *Snapshot) noteUnhashable(path, reason string) {
	if path == "" || reason == "" {
		return
	}
	if s.unhashable == nil {
		s.unhashable = map[string]string{}
	}
	s.unhashable[path] = reason
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

// usrKeys answers the ledger's own spellings for a path: the keys are
// relative, without the leading slash, and both sides of the usrmerge pair
// are tried — dpkg records the spelling it installed, which on a usrmerge
// host may be the /usr-less one.
func usrKeys(path string) []string {
	keys := make([]string, 0, 2)
	for _, variant := range trust.UsrVariants(path) {
		keys = append(keys, strings.TrimPrefix(variant, "/"))
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
