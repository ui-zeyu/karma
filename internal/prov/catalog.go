// Package prov is the distribution's own provenance: which package owns a
// path, what content it recorded, when it was installed, which files the
// administrator diverted, and which ledger files moved. One Catalog answers
// all of those questions, so the audit, the inventory, the package sweep and
// the content ledger read the same database once.
package prov

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"karma/internal/localfs"
	"karma/internal/trust"
)

const (
	// InfoDir is where dpkg keeps per-package lists, hashes and conffile
	// records.
	InfoDir = "/var/lib/dpkg/info"
	// PackageLog is dpkg's transaction log.
	PackageLog = "/var/log/dpkg.log"
	// LogPackage marks the transaction log's own ledger row: it belongs to no
	// package, and a rewrite of it moves the boundary every time judgment
	// rests on.
	LogPackage = "*"
)

const stampLayout = "2006-01-02 15:04:05"

// Ownership is one path's package answer. Known false means the database did
// not answer; Name empty with Known true means no package claims the path.
// Dir marks a path the package records as a directory.
type Ownership struct {
	Name   string
	Known  bool
	Shared bool
	Dir    bool
}

// HashEntry is the content hash dpkg recorded for one path.
type HashEntry struct {
	Pkg  string
	Hash string
}

// LedgerFile is one file the package database owns as metadata: its change
// time is itself evidence when it moves outside a transaction.
type LedgerFile struct {
	Pkg   string
	Path  string
	Stamp time.Time
}

// FileOwner is one package-to-path row.
type FileOwner struct {
	Path    string
	Package string
}

// Catalog is one host's package database. Each table is loaded on first use,
// so a mounts-only run reads no content hashes and a content query reads no
// file lists twice. The context is the run's own: an interrupted run stops
// loading tables at the next file and answers with what was read.
type Catalog struct {
	ctx       context.Context
	kind      string
	note      string
	gaps      []string
	truncated bool

	ownerOnce sync.Once
	owners    map[string]Ownership
	packages  int
	ownerGap  string

	hashOnce sync.Once
	hashes   map[string]HashEntry
	hashGap  string

	conffileOnce sync.Once
	conffileMu   sync.RWMutex
	conffiles    map[string]bool
	conffileGap  string

	timeOnce sync.Once
	times    map[string]time.Time
	timeGap  string

	ledgerOnce  sync.Once
	ledgerFiles []LedgerFile
	ledgerGap   string

	diversionOnce sync.Once
	diversions    map[string]bool

	rpmVerifyOnce sync.Once
	rpmMu         sync.RWMutex
	rpmFlags      map[string]string
	rpmMissing    int
	rpmNote       string
	rpmRan        bool
	rpmGap        string
}

// Open detects the host's package manager. A host with neither database
// answers unknown ownership, never unowned.
func Open(ctx context.Context) *Catalog {
	catalog := &Catalog{kind: "none", ctx: ctx}
	if _, err := os.Stat(InfoDir); err == nil {
		catalog.kind = "dpkg"
		return catalog
	}
	if binary := rpmBinary(); binary != "" {
		catalog.kind = "rpm"
		return catalog
	}
	catalog.note = "no package database: ownership and content evidence are absent"
	return catalog
}

// Kind names the database that answered: dpkg, rpm or none.
func (c *Catalog) Kind() string { return c.kind }

// stopped reports whether the run's context already asked the catalog to stop;
// a catalog assembled without one never stops.
func (c *Catalog) stopped() bool { return c.ctx != nil && c.ctx.Err() != nil }

// cut marks the catalog as read short of its end. A database that stopped
// cannot prove a path unowned: every unknown path then answers unknown, and
// the reason states itself as coverage.
func (c *Catalog) cut(why string) {
	if c.truncated {
		return
	}
	c.truncated = true
	c.gaps = append(c.gaps, "package database read stopped "+why)
}

// fail states a table that could not be read to its end: the table's own gap
// names the error, and the catalog is cut so silence in that table answers
// unknown rather than unowned. A table fails once; the first error stands.
func (c *Catalog) fail(gap *string, what string, err error) {
	if *gap == "" {
		*gap = what + " unreadable: " + err.Error()
	}
	c.cut("at a read error")
}

// budget bounds one manager call by the caller's per-call budget, nested
// under the run's context so an interrupt kills it.
func (c *Catalog) budget(limit time.Duration) (context.Context, context.CancelFunc) {
	if c.ctx == nil {
		return context.WithTimeout(context.Background(), limit)
	}
	return context.WithTimeout(c.ctx, limit)
}

// Gaps are the reads that failed. They are collected lazily, so callers read
// them after the tables they asked for. The whole-database absence statement
// answers through Note, so a caller can state the two with different
// coverage grades.
func (c *Catalog) Gaps() []string {
	if c == nil {
		return nil
	}
	var gaps []string
	gaps = append(gaps, c.gaps...)
	for _, gap := range []string{c.ownerGap, c.hashGap, c.conffileGap, c.timeGap, c.ledgerGap, c.rpmGap} {
		if gap != "" {
			gaps = append(gaps, gap)
		}
	}
	return gaps
}

// Note is the database's own state statement, empty when a database was
// opened: today only "no package database".
func (c *Catalog) Note() string {
	if c == nil {
		return ""
	}
	return c.note
}

// Owned answers the package that owns path, with Known false when the
// database did not answer. It follows the usrmerge spelling both ways.
func (c *Catalog) Owned(path string) (string, bool) {
	ownership := c.Ownership(path)
	return ownership.Name, ownership.Known
}

// OwnedShared is Owned with the directory fact: a row that several packages
// claim is a shared directory, and the first name is a citation.
func (c *Catalog) OwnedShared(path string) (string, bool, bool) {
	ownership := c.Ownership(path)
	return ownership.Name, ownership.Known, ownership.Shared
}

// Ownership answers one path with its shared flag.
func (c *Catalog) Ownership(path string) Ownership {
	if c == nil || path == "" {
		return Ownership{}
	}
	c.ensureOwners()
	if c.ownerGap != "" {
		return Ownership{}
	}
	if ownership, ok := c.owners[path]; ok {
		return ownership
	}
	for _, alias := range usrAliases(path) {
		if ownership, ok := c.owners[alias]; ok {
			return ownership
		}
	}
	// A known database that lists no spelling of the path means unowned —
	// unless the load was cut at an interrupt, when silence proves nothing.
	return Ownership{Known: c.kind != "none" && !c.truncated}
}

// OwnedPath reports whether any package lists the path.
func (c *Catalog) OwnedPath(path string) bool {
	ownership := c.Ownership(path)
	return ownership.Known && ownership.Name != ""
}

// PackageCount is the number of packages the database lists: dpkg's file
// lists, or rpm's package rows. It includes packages that own no regular file
// (metapackages, rpm config-only packages), so it can exceed the names in the
// ownership index.
func (c *Catalog) PackageCount() int {
	if c == nil {
		return 0
	}
	c.ensureOwners()
	return c.packages
}

// OwnerRows returns the whole package-to-path index.
func (c *Catalog) OwnerRows() map[string]Ownership {
	c.ensureOwners()
	return c.owners
}

// Conffile reports a path dpkg records as a configuration file, or rpm marks
// with its config flag.
func (c *Catalog) Conffile(path string) bool {
	if c == nil {
		return false
	}
	c.ensureConffiles()
	c.conffileMu.RLock()
	defer c.conffileMu.RUnlock()
	if c.conffiles[path] {
		return true
	}
	for _, alias := range usrAliases(path) {
		if c.conffiles[alias] {
			return true
		}
	}
	return false
}

// Hash answers the content hash dpkg records for path. rpm records no digest
// in its file list; its verify flags carry the answer instead.
func (c *Catalog) Hash(path string) (HashEntry, bool) {
	if c == nil || c.kind != "dpkg" {
		return HashEntry{}, false
	}
	c.ensureHashes()
	if entry, ok := c.hashes[strings.TrimPrefix(path, "/")]; ok {
		return entry, true
	}
	for _, alias := range usrAliases(path) {
		if entry, ok := c.hashes[strings.TrimPrefix(alias, "/")]; ok {
			return entry, true
		}
	}
	return HashEntry{}, false
}

// Hashes returns the whole recorded hash table, keyed by the path dpkg wrote
// (usually relative, without the leading slash).
func (c *Catalog) Hashes() map[string]HashEntry {
	c.ensureHashes()
	return c.hashes
}

// Timeline answers each package's last transaction.
func (c *Catalog) Timeline() map[string]time.Time {
	c.ensureTimeline()
	return c.times
}

// LedgerFiles returns every package metadata file whose change time is
// evidence, plus dpkg's transaction log when it is non-empty.
func (c *Catalog) LedgerFiles() []LedgerFile {
	c.ensureLedgerFiles()
	return append([]LedgerFile(nil), c.ledgerFiles...)
}

// Diversion reports a path dpkg records as locally diverted. The diversion
// target is the administrator's replacement, not a dropped binary.
func (c *Catalog) Diversion(path string) bool {
	if c == nil || c.kind != "dpkg" {
		return false
	}
	c.ensureDiversions()
	if c.diversions[path] {
		return true
	}
	for _, alias := range usrAliases(path) {
		if c.diversions[alias] {
			return true
		}
	}
	return false
}

// RPMFlags returns the rpm -Va flags for the paths whose content deviates.
// The map is the catalog's own live state; a caller reads it and must not
// write it.
func (c *Catalog) RPMFlags() map[string]string {
	if c == nil || c.kind != "rpm" {
		return nil
	}
	c.ensureRPMVerify()
	c.rpmMu.RLock()
	defer c.rpmMu.RUnlock()
	return c.rpmFlags
}

// RPMVerified reports whether rpm -Va ran to completion, so a judged file with
// no deviation row has a positive content answer.
func (c *Catalog) RPMVerified() bool {
	if c == nil {
		return false
	}
	c.ensureRPMVerify()
	return c.rpmRan
}

// RPMMissing counts packaged files rpm -Va reports absent from disk.
func (c *Catalog) RPMMissing() int {
	if c == nil || c.kind != "rpm" {
		return 0
	}
	c.ensureRPMVerify()
	return c.rpmMissing
}

// RPMNote is the degraded answer from a failed rpm -Va.
func (c *Catalog) RPMNote() string {
	if c == nil || c.kind != "rpm" {
		return ""
	}
	c.ensureRPMVerify()
	return c.rpmNote
}

func (c *Catalog) ensureOwners() {
	c.ownerOnce.Do(func() {
		// A test-built catalog arrives with its index already filled; only an
		// empty one is loaded from the host.
		if c.owners == nil {
			c.owners = map[string]Ownership{}
			switch c.kind {
			case "dpkg":
				c.loadDpkgOwners(InfoDir)
			case "rpm":
				c.loadRPMOwners()
			}
		}
		if c.packages == 0 {
			// The loaders count packages as they read them. A catalog that
			// arrived with its index already filled did not pass through a
			// loader, so its count is the names that index holds.
			seen := map[string]bool{}
			for _, ownership := range c.owners {
				if ownership.Name != "" {
					seen[ownership.Name] = true
				}
			}
			c.packages = len(seen)
		}
	})
}

func (c *Catalog) loadDpkgOwners(infoDir string) {
	c.owners = map[string]Ownership{}
	entries, err := os.ReadDir(infoDir)
	if err != nil {
		c.fail(&c.ownerGap, "package file lists", err)
		return
	}
	for _, entry := range entries {
		if c.stopped() {
			c.cut("at the interrupt")
			return
		}
		name := entry.Name()
		pkg, kind := splitInfoName(name)
		if kind != "list" {
			continue
		}
		c.packages++
		if err := readRows(filepath.Join(infoDir, name), func(line string) {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "/") {
				return
			}
			if existing, ok := c.owners[line]; ok {
				if existing.Name != pkg {
					existing.Shared = true
					c.owners[line] = existing
				}
				return
			}
			c.owners[line] = Ownership{Name: pkg, Known: true}
		}); err != nil {
			c.fail(&c.ownerGap, "package file lists", err)
			return
		}
	}
}

func (c *Catalog) loadRPMOwners() {
	if c.conffiles == nil {
		c.conffiles = map[string]bool{}
	}
	binary := rpmBinary()
	if binary == "" {
		c.ownerGap = "no package file list: the package sweep cannot run"
		c.cut("with the package file lists absent")
		return
	}
	ctx, cancel := c.budget(rpmQueryBudget)
	defer cancel()
	// A scalar inside an array iterator is a one-element array to rpm 4.16,
	// so `[%{NAME} ...]` fails as "different sized arrays" for every package
	// with more than one file. NAME stays outside: one name row, then one
	// flags<TAB>mode<TAB>path row per file. The mode lets the package sweep
	// tell a missing directory from a missing file.
	out, err := run(ctx, binary, "-qa", "--qf", "%{NAME}\n[%{FILEFLAGS}\t%{FILEMODES:octal}\t%{FILENAMES}\n]")
	if err != nil {
		c.fail(&c.ownerGap, "rpm file lists", err)
		return
	}
	pkg := ""
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 3)
		if len(fields) == 1 {
			pkg = fields[0]
			c.packages++
			continue
		}
		if len(fields) != 3 {
			continue
		}
		path := fields[2]
		if pkg == "" || !strings.HasPrefix(path, "/") {
			continue
		}
		flags, _ := strconv.Atoi(fields[0])
		mode, _ := strconv.ParseUint(fields[1], 8, 32)
		dir := mode&0o170000 == 0o040000
		if flags&1 != 0 {
			// A config file is still owned by its package. Dropping it from
			// the ownership index made every rpm conffile read as an orphan.
			c.conffiles[path] = true
		}
		if existing, ok := c.owners[path]; ok {
			if existing.Name != pkg {
				existing.Shared = true
				c.owners[path] = existing
			}
			continue
		}
		c.owners[path] = Ownership{Name: pkg, Known: true, Dir: dir}
	}
	if len(c.owners) == 0 {
		c.fail(&c.ownerGap, "rpm file lists", errors.New("the query answered no rows"))
	}
}

func (c *Catalog) ensureHashes() {
	c.hashOnce.Do(func() {
		if c.hashes == nil {
			c.hashes = map[string]HashEntry{}
			if c.kind == "dpkg" {
				c.loadDpkgHashes(InfoDir)
			}
		}
	})
}

func (c *Catalog) loadDpkgHashes(infoDir string) {
	c.hashes = map[string]HashEntry{}
	entries, err := os.ReadDir(infoDir)
	if err != nil {
		c.fail(&c.hashGap, "package content hashes", err)
		return
	}
	for _, entry := range entries {
		if c.stopped() {
			c.cut("at the interrupt")
			return
		}
		name := entry.Name()
		pkg, kind := splitInfoName(name)
		if kind != "md5sums" {
			continue
		}
		if err := readRows(filepath.Join(infoDir, name), func(line string) {
			hash, path, ok := parseMd5sumsRow(line)
			if ok {
				c.hashes[path] = HashEntry{Pkg: pkg, Hash: hash}
			}
		}); err != nil {
			c.fail(&c.hashGap, "package content hashes", err)
			return
		}
	}
}

func (c *Catalog) ensureConffiles() {
	c.conffileOnce.Do(func() {
		if c.conffiles == nil {
			c.conffiles = map[string]bool{}
		}
		switch c.kind {
		case "dpkg":
			c.loadDpkgConffiles(InfoDir)
		case "rpm":
			// rpm's config flags arrive with its file list, not a separate
			// table.
			c.ensureOwners()
		}
	})
}

func (c *Catalog) loadDpkgConffiles(infoDir string) {
	if c.conffiles == nil {
		c.conffiles = map[string]bool{}
	}
	entries, err := os.ReadDir(infoDir)
	if err != nil {
		c.fail(&c.conffileGap, "package conffile records", err)
		return
	}
	for _, entry := range entries {
		if c.stopped() {
			c.cut("at the interrupt")
			return
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".conffiles") {
			continue
		}
		if err := readRows(filepath.Join(infoDir, name), func(line string) {
			if path, ok := parseConffilesRow(line); ok {
				c.conffiles[path] = true
			}
		}); err != nil {
			c.fail(&c.conffileGap, "package conffile records", err)
			return
		}
	}
}

func (c *Catalog) ensureTimeline() {
	c.timeOnce.Do(func() {
		c.times = map[string]time.Time{}
		switch c.kind {
		case "dpkg":
			for _, path := range packageLogFiles() {
				if c.stopped() {
					c.cut("at the interrupt")
					return
				}
				if err := readPackageLog(path, c.times, c.stopped); err != nil {
					c.fail(&c.timeGap, "package transaction log", err)
					return
				}
			}
			if c.stopped() {
				c.cut("at the interrupt")
			}
		case "rpm":
			c.loadRPMTimeline()
		}
	})
}

func (c *Catalog) loadRPMTimeline() {
	binary := rpmBinary()
	if binary == "" {
		return
	}
	ctx, cancel := c.budget(rpmQueryBudget)
	defer cancel()
	out, err := run(ctx, binary, "-qa", "--qf", "%{NAME}\t%{INSTALLTID}\n")
	if err != nil {
		c.fail(&c.timeGap, "rpm install timeline", err)
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok || name == "" {
			continue
		}
		seconds, err := strconv.ParseInt(value, 10, 64)
		if err != nil || seconds <= 0 {
			continue
		}
		c.times[name] = time.Unix(seconds, 0)
	}
}

func (c *Catalog) ensureLedgerFiles() {
	c.ledgerOnce.Do(func() {
		if c.kind != "dpkg" {
			return
		}
		c.loadDpkgLedgerFiles(InfoDir)
	})
}

func (c *Catalog) loadDpkgLedgerFiles(infoDir string) {
	entries, err := os.ReadDir(infoDir)
	if err != nil {
		c.fail(&c.ledgerGap, "package ledger files", err)
		return
	}
	for _, entry := range entries {
		if c.stopped() {
			c.cut("at the interrupt")
			return
		}
		name := entry.Name()
		pkg, kind := splitInfoName(name)
		if kind != "list" && kind != "md5sums" && kind != "conffiles" {
			continue
		}
		path := filepath.Join(infoDir, name)
		if stamp, _, ok := trust.StatMeta(path); ok {
			c.ledgerFiles = append(c.ledgerFiles, LedgerFile{Pkg: pkg, Path: path, Stamp: time.Unix(stamp, 0)})
		}
	}
	// The log is itself ledger evidence: a rewrite moves the boundary the
	// whole run rests on. A rotated empty file is skipped.
	if info, err := os.Stat(PackageLog); err == nil && info.Size() > 0 {
		if stamp, _, ok := trust.StatMeta(PackageLog); ok {
			c.ledgerFiles = append(c.ledgerFiles, LedgerFile{
				Pkg: LogPackage, Path: PackageLog, Stamp: time.Unix(stamp, 0),
			})
		}
	}
	sort.Slice(c.ledgerFiles, func(i, j int) bool { return c.ledgerFiles[i].Path < c.ledgerFiles[j].Path })
}

func (c *Catalog) ensureDiversions() {
	c.diversionOnce.Do(func() {
		c.diversions = map[string]bool{}
		binary := trustedBinary("dpkg-divert")
		if binary == "" {
			return
		}
		ctx, cancel := c.budget(2 * time.Second)
		defer cancel()
		out, err := run(ctx, binary, "--list")
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(out), "\n") {
			rest, ok := strings.CutPrefix(strings.TrimSpace(line), "local diversion of ")
			if !ok {
				continue
			}
			from, to, found := strings.Cut(rest, " to ")
			if !found {
				continue
			}
			for _, path := range []string{strings.TrimSpace(from), strings.TrimSpace(to)} {
				if path != "" {
					c.diversions[path] = true
				}
			}
		}
	})
}

func (c *Catalog) ensureRPMVerify() {
	c.rpmVerifyOnce.Do(func() {
		c.ensureConffiles()
		c.rpmFlags = map[string]string{}
		if c.conffiles == nil {
			c.conffiles = map[string]bool{}
		}
		binary := rpmBinary()
		if binary == "" {
			return
		}
		ctx, cancel := c.budget(rpmVerifyBudget)
		defer cancel()
		out, err := run(ctx, binary, "-Va")
		if err != nil && !rpmVerifyAnswered(err, out) {
			if ctx.Err() != nil {
				c.rpmNote = "rpm -Va timed out; content evidence is absent"
			} else {
				c.rpmNote = "rpm -Va failed: " + err.Error()
			}
			c.fail(&c.rpmGap, "rpm content verify", err)
			return
		}
		c.rpmRan = true
		c.conffileMu.Lock()
		c.rpmMu.Lock()
		for _, line := range strings.Split(string(out), "\n") {
			path, flags, conffile, absent, ok := parseRpmVerifyLine(line)
			if !ok {
				continue
			}
			if absent {
				c.rpmMissing++
				continue
			}
			if conffile {
				c.conffiles[path] = true
			}
			if strings.ContainsAny(flags, "SM5") {
				c.rpmFlags[path] = flags
			}
		}
		c.rpmMu.Unlock()
		c.conffileMu.Unlock()
	})
}

// rpmVerifyAnswered reports the exit status of a verify that ran to its end:
// rpm exits 1 when it has deviations to report, and that report is the answer.
// Any other failure leaves no content evidence.
func rpmVerifyAnswered(err error, out []byte) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == 1 && len(out) > 0
}

// usrAliases is usrmerge's other spelling for a path: the database records
// /usr/bin while the disk may name /bin, and the reverse.
func usrAliases(path string) []string {
	variants := trust.UsrVariants(path)
	if len(variants) < 2 {
		return nil
	}
	return variants[1:]
}

// packageLogFiles names the transaction log and the rotations logrotate keeps.
func packageLogFiles() []string {
	paths, err := filepath.Glob(PackageLog + "*")
	if err != nil {
		return []string{PackageLog}
	}
	var out []string
	for _, path := range paths {
		if packageLogRotation(filepath.Base(path)) {
			out = append(out, path)
		}
	}
	return out
}

func packageLogRotation(name string) bool {
	rest, ok := strings.CutPrefix(name, filepath.Base(PackageLog))
	if !ok {
		return false
	}
	if rest == "" {
		return true
	}
	if !strings.HasPrefix(rest, ".") {
		return false
	}
	rest = strings.TrimSuffix(rest[1:], ".gz")
	if rest == "" {
		return false
	}
	number, err := strconv.Atoi(rest)
	return err == nil && number > 0 && number <= 31
}

func readPackageLog(path string, times map[string]time.Time, stop func() bool) error {
	file, err := localfs.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	var reader io.Reader = file
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(file)
		if err != nil {
			return err
		}
		defer gz.Close()
		reader = gz
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	scanned := 0
	for scanner.Scan() {
		scanned++
		if scanned%4096 == 0 && stop() {
			return nil
		}
		pkg, stamp, ok := parsePackageLogLine(scanner.Text())
		if !ok {
			continue
		}
		if stamp.After(times[pkg]) {
			times[pkg] = stamp
		}
	}
	return scanner.Err()
}

func parsePackageLogLine(line string) (string, time.Time, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return "", time.Time{}, false
	}
	stamp, err := time.ParseInLocation(stampLayout, fields[0]+" "+fields[1], time.Local)
	if err != nil {
		return "", time.Time{}, false
	}
	index := 3
	if fields[2] == "status" {
		if len(fields) < 5 {
			return "", time.Time{}, false
		}
		index = 4
	}
	pkg, _, _ := strings.Cut(fields[index], ":")
	if pkg == "" {
		return "", time.Time{}, false
	}
	return pkg, stamp, true
}

func splitInfoName(name string) (pkg, kind string) {
	base := name
	if dot := strings.LastIndexByte(base, '.'); dot >= 0 {
		kind = base[dot+1:]
		base = base[:dot]
	}
	if at := strings.IndexByte(base, ':'); at >= 0 {
		base = base[:at]
	}
	return base, kind
}

func readRows(path string, read func(string)) error {
	file, err := localfs.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		read(scanner.Text())
	}
	return scanner.Err()
}

func parseMd5sumsRow(line string) (hash, path string, ok bool) {
	hash, rest, found := strings.Cut(line, "  ")
	if !found {
		hash, rest, found = strings.Cut(line, " ")
	}
	if !found || len(hash) != 32 || rest == "" {
		return "", "", false
	}
	return hash, strings.TrimPrefix(rest, "/"), true
}

func parseConffilesRow(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", false
	}
	path := strings.Fields(line)[0]
	if !strings.HasPrefix(path, "/") {
		return "", false
	}
	return path, true
}

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

// rpmBinaryOverride lets a test fixture point at a stand-in rpm. Production
// always resolves the system directory first.
var rpmBinaryOverride string

func rpmBinary() string {
	if rpmBinaryOverride != "" {
		return rpmBinaryOverride
	}
	return trustedBinary("rpm")
}

// trustedBinary resolves a read-only host tool from the system directories,
// never from the caller's PATH. The environment passed to run also clears the
// loader variables; /etc/ld.so.preload remains the residual trust boundary.
func trustedBinary(name string) string {
	for _, dir := range []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"} {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return path
		}
	}
	return ""
}

const (
	// rpmQueryBudget bounds one rpm query (-qa): the file list and the
	// install timeline are catalog queries, not content verification.
	rpmQueryBudget = 10 * time.Second
	// rpmVerifyBudget bounds the -Va verify, which re-reads every file's
	// digest and is the slow call.
	rpmVerifyBudget = 60 * time.Second
)

func run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/",
		"TMPDIR=/tmp",
		"LANG=C",
		"LC_ALL=C",
	}
	return cmd.Output()
}
