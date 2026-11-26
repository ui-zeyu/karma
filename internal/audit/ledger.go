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
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
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
	file, err := localfs.Open(path)
	if err != nil {
		return "", false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() > hashSizeCap {
		return "", false
	}
	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", false
	}
	return hex.EncodeToString(hash.Sum(nil)), true
}

func hashFiles(ctx context.Context, objects map[string]trust.Facts, expected map[string]ledgerEntry) map[string]string {
	seen := map[string]bool{}
	var paths []string
	for _, facts := range objects {
		if facts.Kind != trust.File || facts.Real == "" || seen[facts.Real] || !ledgerCandidate(facts, expected) {
			continue
		}
		// The object map carries both the asked and the resolved spelling; one
		// hash of the resolved inode answers both.
		seen[facts.Real] = true
		paths = append(paths, facts.Real)
	}
	actual := map[string]string{}
	if len(paths) == 0 {
		return actual
	}
	workers := min(max(runtime.GOMAXPROCS(0), 2), 8)
	if workers > len(paths) {
		workers = len(paths)
	}
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for index := worker; index < len(paths); index += workers {
				if ctx.Err() != nil {
					return
				}
				hash, ok := hashFile(paths[index])
				if !ok {
					continue
				}
				mu.Lock()
				actual[paths[index]] = hash
				mu.Unlock()
			}
		}(worker)
	}
	wg.Wait()
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
		content := Content{Actual: hash, State: Unverified, Method: methodMD5}
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

// overlayRpm folds rpm -Va's deviations into the judged content table. rpm
// carries no per-file digest, so a flagged row is a mismatch with no expected
// hash to quote; the assessor cites the flag word instead. Only judged paths
// enter the table, so an unrelated deviation cannot inflate the summary.
func overlayRpm(verify map[string]Content, flags map[string]string, objects map[string]trust.Facts) {
	if len(flags) == 0 {
		return
	}
	// rpm names the package's spelling; the assessor looks up the resolved
	// spelling. Keep one map from either spelling to the resolved path.
	resolved := make(map[string]string, len(objects)*2)
	for _, facts := range objects {
		if facts.Real == "" {
			continue
		}
		resolved[facts.Real] = facts.Real
		resolved[facts.Path] = facts.Real
	}
	for path, flag := range flags {
		real, judged := resolved[path]
		if !judged {
			continue
		}
		content := verify[real]
		if content.State == Verified {
			// A hash match outranks rpm's own flag: the file may have moved
			// without its content changing.
			continue
		}
		content.State = Mismatched
		content.Method = methodRPM
		content.Actual = "rpm -Va " + flag
		verify[real] = content
	}
}

// overlayRpmVerified records the positive half of rpm -Va: a judged package
// file with no deviation row was checked and matched. Without this, every rpm
// file without a deviation fell back to time and the ledger read 0 verified.
func overlayRpmVerified(verify map[string]Content, objects map[string]trust.Facts, flags map[string]string) {
	for _, facts := range objects {
		if facts.Kind != trust.File || facts.Real == "" || !facts.PackageKnown || facts.Package == "" {
			continue
		}
		if flagged(facts, flags) {
			continue
		}
		if _, seen := verify[facts.Real]; seen {
			continue
		}
		verify[facts.Real] = Content{Package: facts.Package, State: Verified, Method: methodRPM}
	}
}

// flagged reports whether rpm named either spelling of a judged file.
func flagged(facts trust.Facts, flags map[string]string) bool {
	if _, ok := flags[facts.Real]; ok {
		return true
	}
	_, ok := flags[facts.Path]
	return ok
}

// evidenceSet is everything the ledger pass gathered; attachEvidence turns it
// into the snapshot fields the judge reads.
type evidenceSet struct {
	actual      map[string]string
	expected    map[string]ledgerEntry
	conffiles   map[string]bool
	rows        []ledgerFile
	mounts      []Mount
	rpmFlag     map[string]string
	rpmVerified bool
	objects     map[string]trust.Facts
	kind        string
	note        string
	entries     int
	// packages is how many packages the ledger covered. dpkg counts the
	// packages among the judged hash entries; rpm's ledger is a whole-system
	// verify, so it counts every installed package.
	packages int
}

// attachEvidence joins the collected hashes with the ledger, dates the
// packages, and records the tamper verdict.
func (s *Snapshot) attachEvidence(evidence evidenceSet) {
	s.Verify = joinContent(evidence.actual, evidence.expected)
	if evidence.kind == "rpm" {
		overlayRpm(s.Verify, evidence.rpmFlag, evidence.objects)
		if evidence.rpmVerified {
			overlayRpmVerified(s.Verify, evidence.objects, evidence.rpmFlag)
		}
	}
	s.Mounts = evidence.mounts
	s.conffiles = evidence.conffiles
	s.ledgerRows = evidence.rows
	s.tamper = ledgerTamper(s.Boundary, s.PackageTimes, s.ledgerRows)
	verified, mismatched := 0, 0
	for _, content := range s.Verify {
		switch content.State {
		case Verified:
			verified++
		case Mismatched:
			mismatched++
		}
	}
	entries := evidence.entries
	if evidence.kind == "rpm" {
		entries = len(s.Verify)
	}
	s.Ledger = LedgerSummary{
		Kind:       evidence.kind,
		Packages:   evidence.packages,
		Entries:    entries,
		Verified:   verified,
		Mismatched: mismatched,
		Tampered:   tamperedPackages(s.tamper),
		Note:       evidence.note,
	}
	s.ledgerReady = true
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
	for _, path := range paths {
		facts := s.Facts(path)
		if facts.Kind != trust.File || facts.Real == "" {
			continue
		}
		if _, seen := s.Verify[facts.Real]; seen {
			continue
		}
		if content, ok := s.contentFor(facts); ok {
			s.Verify[facts.Real] = content
		}
	}
}

// contentFor asks the catalog for one judged file's content answer.
func (s *Snapshot) contentFor(facts trust.Facts) (Content, bool) {
	switch s.Ledger.Kind {
	case "dpkg":
		entry, ok := s.catalog.Hash(facts.Real)
		if !ok && facts.Path != facts.Real {
			entry, ok = s.catalog.Hash(facts.Path)
		}
		if !ok {
			return Content{}, false
		}
		hash, ok := hashFile(facts.Real)
		if !ok {
			return Content{}, false
		}
		state := Unverified
		if hash == entry.Hash {
			state = Verified
		} else {
			state = Mismatched
		}
		return Content{Package: entry.Pkg, Expected: entry.Hash, Actual: hash, State: state, Method: methodMD5}, true
	case "rpm":
		if !s.catalog.RPMVerified() {
			return Content{}, false
		}
		flags := s.catalog.RPMFlags()
		if flag, ok := flags[facts.Real]; ok {
			return Content{Package: facts.Package, State: Mismatched, Method: methodRPM, Actual: "rpm -Va " + flag}, true
		}
		if flag, ok := flags[facts.Path]; ok {
			return Content{Package: facts.Package, State: Mismatched, Method: methodRPM, Actual: "rpm -Va " + flag}, true
		}
		if facts.PackageKnown && facts.Package != "" {
			return Content{Package: facts.Package, State: Verified, Method: methodRPM}, true
		}
	}
	return Content{}, false
}

// ledgerPackages counts the packages a dpkg hash table covers.
func ledgerPackages(expected map[string]ledgerEntry) int {
	seen := map[string]bool{}
	for _, entry := range expected {
		seen[entry.pkg] = true
	}
	return len(seen)
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

// dpkgExpected keeps the hash rows for paths the snapshot judged, under every
// spelling the ledger may use. No file facts means no expected rows.
func dpkgExpected(hashes map[string]prov.HashEntry, objects map[string]trust.Facts) map[string]ledgerEntry {
	keys := map[string]bool{}
	for _, facts := range objects {
		if facts.Kind != trust.File {
			continue
		}
		for _, path := range []string{facts.Path, facts.Real} {
			if path == "" {
				continue
			}
			for _, key := range usrKeys(path) {
				keys[key] = true
			}
		}
	}
	expected := map[string]ledgerEntry{}
	if len(keys) == 0 {
		return expected
	}
	for key, entry := range hashes {
		if !keys[key] {
			continue
		}
		expected[key] = ledgerEntry{pkg: entry.Pkg, hash: entry.Hash}
	}
	return expected
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
