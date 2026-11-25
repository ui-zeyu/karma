package audit

// The content ledger: what the distribution says it shipped, compared against
// what the disk carries. dpkg keeps a per-file md5 beside every package's
// list; rpm answers a whole-system verify through rpm -Va. A mismatch convicts
// a file whose timestamps were cleaned, and a match acquits one whose
// timestamps a package upgrade moved — the two evidence lines that time alone
// cannot give.

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

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
	FSType string
	Path   string
	Opts   string
}

// LedgerSummary says which content ledger the run used and how far it reached.
type LedgerSummary struct {
	Kind     string   // dpkg, rpm, none
	Packages int      // packages whose content hashes were compared
	Entries  int      // ledger hash entries read for those packages
	Verified int      // judged files whose content matched the ledger
	Tampered []string // packages whose ledger files changed after their last transaction
	Note     string   // a degraded answer worth a coverage line
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
	file, err := os.Open("/proc/self/mounts")
	if err != nil {
		return nil
	}
	defer file.Close()
	var mounts []Mount
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		mount, ok := parseMountsLine(scanner.Text())
		if ok {
			mounts = append(mounts, mount)
		}
	}
	return mounts
}

// ledgerEntry is one expected content hash: the package and the md5 its
// ledger records for a path (kept without the leading slash, as dpkg writes).
type ledgerEntry struct{ pkg, hash string }

// ledgerFile is one package's ledger file and when it last changed.
type ledgerFile struct {
	Pkg   string
	Stamp time.Time
	Path  string
}

// logLedgerPkg marks the transaction-log row inside the ledger file set: the
// log itself is evidence, and rewriting it moves the boundary.
const logLedgerPkg = "*"

// usrKeys spells a path the ways the ledger may record it. dpkg wrote /bin
// spellings before the usrmerge and /usr/bin spellings after it, and the
// comparison must survive both.
func usrKeys(path string) []string {
	key := strings.TrimPrefix(path, "/")
	if rest, ok := strings.CutPrefix(key, "usr/"); ok {
		return []string{key, rest}
	}
	return []string{key}
}

// hashSizeCap skips hashing huge images: a ledger comparison over a multi-gigabyte
// store would dominate the run, and such a file is no plausible implant.
const hashSizeCap = 128 << 20

// hashFile answers the md5 of a regular file within the size cap.
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
	digest := md5.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", false
	}
	return hex.EncodeToString(digest.Sum(nil)), true
}

// hashFiles reads every collected regular file once and answers hash by path,
// under both the asked and the resolved spelling.
func hashFiles(ctx context.Context, objects map[string]trust.Facts) map[string]string {
	actual := map[string]string{}
	for _, facts := range objects {
		if ctx.Err() != nil {
			break
		}
		if facts.Kind != trust.File || facts.Real == "" {
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

// joinContent pairs each actual hash with the ledger entry recorded for the
// same file, under any spelling the ledger may have used.
func joinContent(actual map[string]string, expected map[string]ledgerEntry) map[string]Content {
	verify := map[string]Content{}
	for path, hash := range actual {
		content := Content{Actual: hash, State: Unverified}
		for _, key := range usrKeys(path) {
			if entry, hit := expected[key]; hit {
				content.Package, content.Expected = entry.pkg, entry.hash
				if entry.hash == hash {
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

// overlayRpm marks rpm -Va deviations. rpm answers "this file differs" without
// printing either hash, so the row convicts only where no ledger entry did.
func overlayRpm(verify map[string]Content, flags map[string]string) {
	for path := range flags {
		content, seen := verify[path]
		if !seen {
			verify[path] = Content{State: Mismatched}
			continue
		}
		if content.State == Unverified {
			content.State = Mismatched
			verify[path] = content
		}
	}
}

// mergeTimes folds a package timeline into a snapshot's, keeping the later
// stamp per package so dpkg and rpm answers can coexist.
func mergeTimes(dst, src map[string]time.Time) map[string]time.Time {
	if dst == nil {
		dst = map[string]time.Time{}
	}
	for pkg, stamp := range src {
		if stamp.After(dst[pkg]) {
			dst[pkg] = stamp
		}
	}
	return dst
}

// evidenceSet is everything the ledger pass gathered; attachEvidence turns it
// into the snapshot fields the judge reads.
type evidenceSet struct {
	times     map[string]time.Time
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
	s.PackageTimes = mergeTimes(s.PackageTimes, evidence.times)
	s.Verify = joinContent(evidence.actual, evidence.expected)
	overlayRpm(s.Verify, evidence.rpmFlag)
	s.Mounts = evidence.mounts
	s.conffiles = evidence.conffiles
	s.tamper = ledgerTamper(s.PackageTimes, evidence.rows)
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
	var tampered []string
	seen := map[string]bool{}
	for _, row := range s.tamper {
		if row.Pkg == logLedgerPkg || seen[row.Pkg] {
			continue
		}
		seen[row.Pkg] = true
		tampered = append(tampered, row.Pkg)
	}
	s.Ledger = LedgerSummary{
		Kind:     evidence.kind,
		Packages: len(packages),
		Entries:  len(evidence.expected),
		Verified: verified,
		Tampered: tampered,
		Note:     evidence.note,
	}
}

// tamperMargin is how far a ledger write may sit past the ledger's typical
// write before it is a tamper candidate, not the artifact's own birth: a
// container image build extracts every file at once and moves all the stamps
// uniformly past the log, sometimes layer by layer.
const tamperMargin = 6 * time.Hour

// ledgerTamper answers which ledger files changed after their package's last
// recorded transaction AND well after the ledger's typical write. A
// legitimate ledger write lands during unpack, before the transaction's
// closing status line; a uniform shift past the log is the artifact being
// built, and only an outlier past that baseline is a writer outside the
// package manager touching the verification data.
func ledgerTamper(times map[string]time.Time, rows []ledgerFile) []ledgerFile {
	baseline := medianStamp(rows)
	var out []ledgerFile
	for _, row := range rows {
		stamp, ok := times[row.Pkg]
		if !ok || !row.Stamp.After(stamp) {
			continue
		}
		if !row.Stamp.After(baseline.Add(tamperMargin)) {
			continue
		}
		out = append(out, row)
	}
	return out
}

// medianStamp is the ledger's typical write time.
func medianStamp(rows []ledgerFile) time.Time {
	if len(rows) == 0 {
		return time.Time{}
	}
	sorted := append([]ledgerFile(nil), rows...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Stamp.Before(sorted[j].Stamp) })
	return sorted[len(sorted)/2].Stamp
}

// packageLogTamper asks whether the transaction log was rewritten after its
// newest entry: the log is itself ledger evidence, and inserting an old
// transaction into it moves the boundary. A rotation or an image build writes
// a fresh file whose stamp sits with the rest, so only a write past the
// ledger's baseline reads as a rewrite.
func packageLogTamper(times map[string]time.Time, stamp, baseline time.Time) (ledgerFile, bool) {
	var latest time.Time
	for _, value := range times {
		if value.After(latest) {
			latest = value
		}
	}
	if latest.IsZero() || !stamp.After(latest.Add(packageLogMargin)) {
		return ledgerFile{}, false
	}
	if !stamp.After(baseline.Add(tamperMargin)) {
		return ledgerFile{}, false
	}
	return ledgerFile{Pkg: logLedgerPkg, Stamp: stamp, Path: packageLog}, true
}

// dpkgInfoDir is where dpkg keeps per-package lists, content hashes and
// conffile records.
const dpkgInfoDir = "/var/lib/dpkg/info"

// readDpkgLedger reads the content ledger straight from dpkg's files: the
// expected hash of every packaged file the run judged, the conffile records,
// and the change times of the ledger files themselves. The hash files are read
// only for the packages the run judged; the ledger stamps are read for every
// package, because a tampered ledger matters even beyond the candidate set.
func readDpkgLedger(ctx context.Context, infoDir string, candidatePkgs map[string]bool) (expected map[string]ledgerEntry, conffiles map[string]bool, rows []ledgerFile, ok bool) {
	entries, err := os.ReadDir(infoDir)
	if err != nil {
		return nil, nil, nil, false
	}
	expected = map[string]ledgerEntry{}
	conffiles = map[string]bool{}
	for _, entry := range entries {
		if ctx.Err() != nil {
			break
		}
		name := entry.Name()
		pkg, kind := splitInfoName(name)
		path := infoDir + "/" + name
		switch kind {
		case "md5sums":
			if stamp, _, statOk := trust.StatMeta(path); statOk {
				rows = append(rows, ledgerFile{Pkg: pkg, Stamp: time.Unix(stamp, 0), Path: path})
			}
			if candidatePkgs != nil && !candidatePkgs[pkg] {
				continue
			}
			readRows(path, func(line string) {
				hash, file, ok := parseMd5sumsRow(line)
				if ok {
					expected[file] = ledgerEntry{pkg: pkg, hash: hash}
				}
			})
		case "list":
			if stamp, _, statOk := trust.StatMeta(path); statOk {
				rows = append(rows, ledgerFile{Pkg: pkg, Stamp: time.Unix(stamp, 0), Path: path})
			}
		case "conffiles":
			if candidatePkgs != nil && !candidatePkgs[pkg] {
				continue
			}
			readRows(path, func(line string) {
				if file, ok := parseConffilesRow(line); ok {
					conffiles[file] = true
				}
			})
		}
	}
	return expected, conffiles, rows, true
}

// splitInfoName reads a dpkg info file's package and kind:
// `libc6:amd64.md5sums` is package libc6, kind md5sums.
func splitInfoName(name string) (string, string) {
	base, kind, found := strings.Cut(name, ".")
	if !found {
		return "", ""
	}
	pkg, _, _ := strings.Cut(base, ":")
	return pkg, kind
}

func readRows(path string, read func(string)) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		read(scanner.Text())
	}
}

// parseMd5sumsRow reads one dpkg md5sums line: `hash  usr/bin/ls`, the path
// without its leading slash.
func parseMd5sumsRow(line string) (hash, path string, ok bool) {
	fields := strings.Fields(line)
	if len(fields) != 2 || len(fields[0]) != 32 {
		return "", "", false
	}
	return fields[0], fields[1], true
}

// parseConffilesRow reads one dpkg conffiles line: the absolute path of a
// file an administrator is expected to edit.
func parseConffilesRow(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "/") {
		return "", false
	}
	return line, true
}

// parseTimelineRow reads one `pkg epoch` row: dpkg.log condensed on the
// target, or rpm's install transaction ids.
func parseTimelineRow(line string) (string, time.Time, bool) {
	fields := strings.Fields(line)
	if len(fields) != 2 {
		return "", time.Time{}, false
	}
	seconds, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || seconds <= 0 {
		return "", time.Time{}, false
	}
	return fields[0], time.Unix(seconds, 0), true
}

func parseTimelineRows(text string) map[string]time.Time {
	times := map[string]time.Time{}
	for _, line := range strings.Split(text, "\n") {
		pkg, stamp, ok := parseTimelineRow(line)
		if !ok {
			continue
		}
		if stamp.After(times[pkg]) {
			times[pkg] = stamp
		}
	}
	return times
}

// rpmQueryBudget bounds one rpm call; a verify of a whole system takes the
// longer budget.
const (
	rpmQueryBudget   = 10 * time.Second
	rpmVerifyBudget  = 60 * time.Second
	packageLogMargin = time.Hour
)

func rpmBinary() string {
	path, _ := exec.LookPath("rpm")
	return path
}

// readRpmVerify runs rpm -Va and answers the rows whose content flags deviate
// (S size, M mode, 5 digest). Config files are expected to differ from the
// package copy and are returned separately, as rpm's own `c` marker names them.
func readRpmVerify(ctx context.Context) (mismatch map[string]string, conffiles map[string]bool, missing int, note string) {
	binary := rpmBinary()
	if binary == "" {
		return nil, nil, 0, ""
	}
	ctx, cancel := context.WithTimeout(ctx, rpmVerifyBudget)
	defer cancel()
	out, err := exec.CommandContext(ctx, binary, "-Va").Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, 0, "rpm -Va timed out; content evidence is absent"
		}
		return nil, nil, 0, "rpm -Va failed: " + err.Error()
	}
	mismatch = map[string]string{}
	conffiles = map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		path, flags, conffile, absent, ok := parseRpmVerifyLine(line)
		if !ok {
			continue
		}
		if absent {
			missing++
			continue
		}
		if conffile {
			conffiles[path] = true
			continue
		}
		if strings.ContainsAny(flags, "SM5") {
			mismatch[path] = flags
		}
	}
	return mismatch, conffiles, missing, ""
}

// parseRpmVerifyLine reads one rpm -Va row: `SM5....T.  /usr/bin/x`,
// `..5....T.  c /etc/hosts`, or `missing  /usr/bin/x`.
func parseRpmVerifyLine(line string) (path, flags string, conffile, absent, ok bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 {
		return "", "", false, false, false
	}
	if fields[0] == "missing" {
		return fields[len(fields)-1], "", false, true, true
	}
	flags = fields[0]
	if !rpmVerifyFlags(flags) {
		return "", "", false, false, false
	}
	index := 1
	if fields[index] == "c" {
		conffile = true
		index++
	}
	if index >= len(fields) {
		return "", "", false, false, false
	}
	return fields[index], flags, conffile, false, true
}

func rpmVerifyFlags(flags string) bool {
	if len(flags) < 8 {
		return false
	}
	for _, flag := range flags {
		switch flag {
		case '.', 'S', 'M', '5', 'D', 'L', 'U', 'G', 'T', 'P':
		default:
			return false
		}
	}
	return true
}

// readRpmTimeline dates each package's install transaction. INSTALLTID is the
// transaction's epoch, the rpm counterpart of a dpkg.log line.
func readRpmTimeline(ctx context.Context) map[string]time.Time {
	binary := rpmBinary()
	if binary == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, rpmQueryBudget)
	defer cancel()
	out, err := exec.CommandContext(ctx, binary, "-qa", "--qf", "%{NAME} %{INSTALLTID}\n").Output()
	if err != nil {
		return nil
	}
	return parseTimelineRows(string(out))
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
	if len(packages) == 0 {
		return nil
	}
	return packages
}

// shortHash clips a hash for an evidence line: the operator reads enough to
// compare by eye, never the whole digest.
func shortHash(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}
