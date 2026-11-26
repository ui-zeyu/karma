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
	"runtime"
	"sort"
	"strings"
	"sync"
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

// packageOwnerSkip keeps the sweep out of documentation trees and the package
// database itself; a modified manual page is not an execution surface.
var packageOwnerSkip = []string{
	"/usr/share/doc", "/usr/share/man", "/usr/share/locale", "/usr/share/info",
	"/usr/share/help", "/usr/share/gtk-doc", "/usr/share/icons", "/usr/share/fonts",
	"/usr/share/zoneinfo", "/usr/share/pixmaps", "/usr/share/backgrounds",
	"/usr/share/sounds", "/usr/share/games", "/var/lib/dpkg", "/var/lib/rpm",
	"/var/lib/apt/lists",
}

// packageEntry is one recorded path before the worker-pool stat pass.
type packageEntry struct {
	Path string
	Pkg  string
}

// collectPackages stats every recorded package file and records the edges the
// package transaction no longer explains.
func collectPackages(ctx context.Context, snapshot *Snapshot) []string {
	catalog := snapshot.catalog
	if catalog == nil || catalog.Kind() == "none" {
		return []string{"no package database: the package sweep cannot run"}
	}
	state := &snapshot.Packages
	state.Kind = catalog.Kind()
	owners := catalog.OwnerRows()
	if len(owners) == 0 {
		for _, gap := range catalog.Gaps() {
			if strings.Contains(gap, "file list") {
				return []string{gap}
			}
		}
		return []string{"package file list is empty: the package sweep cannot run"}
	}
	state.Packages = countPackages(owners)
	boundary := snapshot.Boundary.Time
	var gaps []string
	entries := make([]packageEntry, 0, len(owners))
	for path, ownership := range owners {
		if len(entries) >= packageSweepLimit {
			gaps = append(gaps, fmt.Sprintf("package sweep stopped at %d files", packageSweepLimit))
			break
		}
		if packageOwnerSkipPath(path) || catalog.Diversion(path) || catalog.Conffile(path) {
			continue
		}
		entries = append(entries, packageEntry{Path: path, Pkg: ownership.Name})
	}
	workers := min(max(runtime.GOMAXPROCS(0)*2, 2), 16)
	chunk := (len(entries) + workers - 1) / workers
	var (
		mu        sync.Mutex
		anomalies []PackageFile
		files     int
		wg        sync.WaitGroup
	)
	for worker := 0; worker < workers; worker++ {
		start := worker * chunk
		end := min(start+chunk, len(entries))
		if start >= end {
			break
		}
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			var local []PackageFile
			localFiles := 0
			for _, entry := range entries[start:end] {
				if ctx.Err() != nil {
					break
				}
				stamp, known := snapshot.PackageTimes[entry.Pkg]
				if !known || stamp.IsZero() {
					if boundary.IsZero() {
						continue
					}
					stamp = boundary
				}
				info, err := os.Lstat(entry.Path)
				if err != nil {
					if os.IsNotExist(err) {
						local = append(local, PackageFile{
							Path: entry.Path, Package: entry.Pkg, Missing: true, Transaction: stamp,
						})
					}
					continue
				}
				if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
					continue
				}
				ctime := trust.CTime(info)
				localFiles++
				if ctime <= stamp.Unix() {
					continue
				}
				local = append(local, PackageFile{
					Path: entry.Path, Package: entry.Pkg, CTime: ctime, Transaction: stamp,
				})
			}
			mu.Lock()
			anomalies = append(anomalies, local...)
			files += localFiles
			mu.Unlock()
		}(start, end)
	}
	wg.Wait()
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

func countPackages(owners map[string]prov.Ownership) int {
	seen := map[string]bool{}
	for _, ownership := range owners {
		if ownership.Name != "" {
			seen[ownership.Name] = true
		}
	}
	return len(seen)
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
func judgePackages(snapshot *Snapshot, filter Filter, add func(Finding)) []string {
	state := &snapshot.Packages
	if state.Kind == "" || len(state.Anomalies) == 0 {
		return nil
	}
	boundary := snapshot.Boundary.Time
	var anomalies []PackageFile
	for _, anomaly := range state.Anomalies {
		if !pathInScope(anomaly.Path, filter) {
			continue
		}
		// A file older than the artifact edge came with the image, even when
		// the image layer rebuilt its ctime after the package transaction.
		if !anomaly.Missing && !boundary.IsZero() && anomaly.CTime <= boundary.Unix() {
			continue
		}
		anomalies = append(anomalies, anomaly)
	}
	var coverage []string
	shown := 0
	for _, anomaly := range anomalies {
		if shown >= 100 {
			coverage = append(coverage, fmt.Sprintf("%d more package-file anomalies than the report shows", len(anomalies)-shown))
			break
		}
		shown++
		class := "package-file-modified"
		title := "package file changed after its package transaction"
		origin := Modified
		evidence := []string{
			fmt.Sprintf("package %s owns %s", anomaly.Package, anomaly.Path),
			fmt.Sprintf("ctime %s is after the package's last transaction %s",
				ctimeString(anomaly.CTime), anomaly.Transaction.Format(stampLayout)),
		}
		if anomaly.Missing {
			class = "package-file-missing"
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
			Trace:    steps("package "+anomaly.Package, "file "+anomaly.Path, class),
		})
	}
	return coverage
}

func packageFileSeverity(path string) Severity {
	if underAny(path, trustedExecutionRoots) {
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
	if underAny(path, trustedExecutionRoots) {
		return RootAsset
	}
	if strings.HasPrefix(path, "/etc/") {
		return RootAsset
	}
	return ServiceAsset
}

var trustedExecutionRoots = []string{
	"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec",
	"/lib", "/lib64", "/usr/lib64",
}

func underAny(path string, roots []string) bool {
	for _, root := range roots {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}
