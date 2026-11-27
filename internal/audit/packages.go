package audit

// The package sweep is the global provenance graph: every file a package's
// own file list records is joined to that package's last transaction. A file
// whose inode changed after the transaction is a broken ownership edge, even
// when it is not on an activation path and its content was never hashed. The
// content ledger stays the precise answer for the judged set; this sweep is
// how a dormant replaced library or a deleted package file becomes visible.

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"karma/internal/prov"
	"karma/internal/trust"
)

// PackageFile is one broken package-to-file edge.
type PackageFile struct {
	Path        string
	Package     string
	CTime       int64
	Transaction time.Time
	Missing     bool
}

// PackageState is the package-domain answer.
type PackageState struct {
	Kind      string
	Packages  int
	Files     int
	Anomalies []PackageFile
}

const packageSweepLimit = 250000

// packageOwnerSkip keeps the sweep out of documentation trees, the package
// database itself, and scheduler state; a modified manual page or anacron
// stamp is not an execution surface.
var packageOwnerSkip = []string{
	"/usr/share/doc", "/usr/share/man", "/usr/share/locale", "/usr/share/info",
	"/usr/share/help", "/usr/share/gtk-doc", "/usr/share/icons", "/usr/share/fonts",
	"/usr/share/zoneinfo", "/usr/share/pixmaps", "/usr/share/backgrounds",
	"/usr/share/sounds", "/usr/share/games", "/var/lib/dpkg", "/var/lib/rpm",
	"/var/lib/apt/lists",
	// Anacron rewrites its stamps on the scheduler's own timetable.
	"/var/spool/anacron",
}

// packageEntry is one recorded path before the worker-pool stat pass.
type packageEntry struct {
	Path string
	Pkg  string
}

// collectPackages stats every recorded package file and records the edges the
// package transaction no longer explains.
func collectPackages(ctx context.Context, snapshot *Snapshot) []Coverage {
	catalog := snapshot.catalog
	if catalog == nil || catalog.Kind() == "none" {
		return []Coverage{coverageAbsent("packages", "no package database: the package sweep cannot run")}
	}
	state := &snapshot.Packages
	state.Kind = catalog.Kind()
	owners := catalog.OwnerRows()
	if len(owners) == 0 {
		for _, gap := range catalog.Gaps() {
			if strings.Contains(gap, "file list") {
				return []Coverage{coverageGap("packages", gap)}
			}
		}
		return []Coverage{coverageAbsent("packages", "package file list is empty: the package sweep cannot run")}
	}
	state.Packages = catalog.PackageCount()
	boundary := snapshot.Boundary.Time
	var gaps []Coverage
	entries := make([]packageEntry, 0, len(owners))
	for path, ownership := range owners {
		if !snapshot.plan.Filter.touchesPath(path) {
			continue
		}
		if len(entries) >= packageSweepLimit {
			gaps = append(gaps, coverageGap("packages", fmt.Sprintf("package sweep stopped at %d files", packageSweepLimit)))
			break
		}
		// A package-recorded directory has no execution edge. Existing ones
		// were skipped after the stat; a missing directory must not read as a
		// broken file edge.
		if !sweepEligible(path, ownership, catalog) {
			continue
		}
		entries = append(entries, packageEntry{Path: path, Pkg: ownership.Name})
	}
	workers := workerCount(2)
	locals := make([][]PackageFile, workers)
	counts := make([]int, workers)
	each(ctx, len(entries), workers, func(w, i int) {
		entry := entries[i]
		stamp, known := snapshot.PackageTimes[entry.Pkg]
		if !known || stamp.IsZero() {
			if boundary.IsZero() {
				return
			}
			stamp = boundary
		}
		info, err := os.Lstat(entry.Path)
		if err != nil {
			if os.IsNotExist(err) {
				locals[w] = append(locals[w], PackageFile{
					Path: entry.Path, Package: entry.Pkg, Missing: true, Transaction: stamp,
				})
			}
			return
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return
		}
		ctime := trust.CTime(info)
		counts[w]++
		if ctime <= stamp.Unix() {
			return
		}
		locals[w] = append(locals[w], PackageFile{
			Path: entry.Path, Package: entry.Pkg, CTime: ctime, Transaction: stamp,
		})
	})
	var anomalies []PackageFile
	files := 0
	for w := range locals {
		anomalies = append(anomalies, locals[w]...)
		files += counts[w]
	}
	state.Anomalies = anomalies
	state.Files = files
	sort.Slice(state.Anomalies, func(i, j int) bool {
		if state.Anomalies[i].Package != state.Anomalies[j].Package {
			return state.Anomalies[i].Package < state.Anomalies[j].Package
		}
		return state.Anomalies[i].Path < state.Anomalies[j].Path
	})
	return gaps
}

// sweepEligible reports whether a package-recorded path belongs in the ctime
// sweep: a regular file outside the documentation, package and scheduler
// state trees, not diverted and not a conffile.
func sweepEligible(path string, ownership prov.Ownership, catalog *prov.Catalog) bool {
	if ownership.Dir || packageOwnerSkipPath(path) {
		return false
	}
	return !catalog.Diversion(path) && !catalog.Conffile(path)
}

func packageOwnerSkipPath(path string) bool {
	for _, prefix := range packageOwnerSkip {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

// judgePackages turns broken package edges into findings. Severity follows the
// path's execution role: a system binary or library is root-reachable; a
// package file elsewhere is lower.
func judgePackages(j *judgePass) []Coverage {
	snapshot, add := j.snapshot, j.add
	state := &snapshot.Packages
	if state.Kind == "" || len(j.view.PackageFiles) == 0 {
		return nil
	}
	boundary := snapshot.Boundary.Time
	var anomalies []PackageFile
	for _, anomaly := range j.view.PackageFiles {
		// A file older than the artifact edge came with the image, even when
		// the image layer rebuilt its ctime after the package transaction.
		if !anomaly.Missing && !boundary.IsZero() && anomaly.CTime <= boundary.Unix() {
			continue
		}
		anomalies = append(anomalies, anomaly)
	}
	var coverage []Coverage
	anomalies, coverage = shownMore(anomalies, 100, "packages", "package-file anomalies")
	for _, anomaly := range anomalies {
		class := Class("package-file-modified")
		title := "package file changed after its package transaction"
		origin := Modified
		evidence := []string{
			fmt.Sprintf("package %s owns %s", anomaly.Package, anomaly.Path),
			fmt.Sprintf("ctime %s is after the package's last transaction %s",
				ctimeString(anomaly.CTime), anomaly.Transaction.Format(stampLayout)),
		}
		if anomaly.Missing {
			class = Class("package-file-missing")
			title = "package file missing from disk"
			origin = Unknown
			evidence = []string{
				fmt.Sprintf("package %s records %s", anomaly.Package, anomaly.Path),
				"the path does not exist on disk",
				fmt.Sprintf("the package's last transaction %s", anomaly.Transaction.Format(stampLayout)),
			}
		}
		add(Finding{
			Class: class, Severity: packageFileSeverity(anomaly.Path), Title: title,
			Path: anomaly.Path, Origin: origin, Reach: packageFileReach(anomaly.Path),
			Detail:   fmt.Sprintf("package %s's ownership edge is broken", anomaly.Package),
			Evidence: evidence,
			Trace:    steps("package "+anomaly.Package, "file "+anomaly.Path, string(class)),
		})
	}
	return coverage
}

func packageFileSeverity(path string) Severity {
	if trust.UnderAny(path, programTrees) {
		return High
	}
	switch {
	case strings.HasPrefix(path, "/etc/"):
		return Medium
	case strings.HasPrefix(path, "/var/www/"), strings.HasPrefix(path, "/srv/"):
		return Medium
	}
	if strings.Contains(path, "/bin/") || strings.HasSuffix(path, ".so") || strings.Contains(path, ".so.") {
		return Medium
	}
	return Low
}

func packageFileReach(path string) Reach {
	if trust.UnderAny(path, programTrees) {
		return RootAsset
	}
	if strings.HasPrefix(path, "/etc/") {
		return RootAsset
	}
	return ServiceAsset
}
