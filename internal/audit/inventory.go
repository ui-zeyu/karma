package audit

// The static inventory: the package manager's file lists against the disk's
// program directories. An executable no package records is evidence even
// before it runs; it does not have to sit on an activation path to be named.

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"karma/internal/trust"
)

// inventoryRoots are the distribution's program directories. They are flat
// (or nearly so) and almost every entry is package-owned, which keeps the
// difference meaningful. /usr/local is the administrator's tree and /usr/lib
// carries generated files; neither is a default.
var inventoryRoots = []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/libexec"}

const inventoryBudget = 20000

// UnownedFile is one executable no package's file list claims.
type UnownedFile struct {
	Path      string
	Dir       string
	Total     int // entries in the directory
	Owned     int // entries in the directory a package claims
	RootOwned bool
	// Root marks an executable directly under /, the container entrypoint
	// layer rather than a program directory.
	Root bool
	Mode fs.FileMode
}

// collectInventory walks the plan's roots and records the executables no
// package owns. Only files outside the active judgment set are recorded: an
// activation target or a process image is already judged by its own check.
// collectFiles is the files domain's collection: the program directories,
// plus the entrypoint layer at the filesystem root.
func collectFiles(ctx context.Context, snapshot *Snapshot) []Coverage {
	plan := snapshot.plan
	gaps := collectInventory(ctx, snapshot, plan)
	// The root layer is cheap to read and stays outside every InventoryRoot;
	// the path filter keeps it out of a scoped report when it is not named.
	gaps = append(gaps, collectRootScripts(ctx, snapshot)...)
	// A path scope can read the same root file through the parent walk and
	// the entrypoint scan; the root description wins.
	snapshot.Unowned = dedupeUnowned(snapshot.Unowned)
	return gaps
}

func dedupeUnowned(files []UnownedFile) []UnownedFile {
	if len(files) < 2 {
		return files
	}
	out := make([]UnownedFile, 0, len(files))
	index := make(map[string]int, len(files))
	for _, file := range files {
		if at, ok := index[file.Path]; ok {
			if file.Root && !out[at].Root {
				out[at] = file
			}
			continue
		}
		index[file.Path] = len(out)
		out = append(out, file)
	}
	return out
}

// collectRootScripts names executables at / itself. A container entrypoint or
// a dropped payload at the root is outside every program directory, and the
// static inventory would otherwise never see it.
func collectRootScripts(ctx context.Context, snapshot *Snapshot) []Coverage {
	if snapshot.catalog == nil || snapshot.catalog.Kind() == "none" {
		return nil
	}
	files, total, owned, err := scanRootScripts(ctx, "/", func(path string) bool {
		return snapshot.catalog.OwnedPath(path) || snapshot.catalog.Diversion(path)
	}, activePaths(snapshot))
	if err != nil {
		return []Coverage{coverageGap("files", "root entrypoint scan: "+err.Error())}
	}
	if len(files) == 0 {
		return nil
	}
	for index := range files {
		files[index].Total = total
		files[index].Owned = owned
	}
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.Path)
	}
	snapshot.ensureFacts(paths)
	snapshot.Unowned = append(snapshot.Unowned, files...)
	return nil
}

// scanRootScripts reads one directory's immediate entries; it is separate
// from the recursive inventory so a test can point it at a fixture.
func scanRootScripts(ctx context.Context, root string, owned func(string) bool, active map[string]bool) ([]UnownedFile, int, int, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, 0, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, 0, 0, err
	}
	total := len(entries)
	ownedCount := 0
	var files []UnownedFile
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		path := filepath.Join(root, entry.Name())
		if owned(path) {
			ownedCount++
			continue
		}
		if active[path] {
			continue
		}
		files = append(files, UnownedFile{
			Path: path, Dir: root, Root: true,
			RootOwned: trust.Owner(info) == 0, Mode: info.Mode(),
		})
	}
	return files, total, ownedCount, nil
}

func collectInventory(ctx context.Context, snapshot *Snapshot, plan Plan) []Coverage {
	roots := plan.InventoryRoots
	if len(roots) == 0 {
		roots = inventoryRoots
	}
	catalog := snapshot.catalog
	if catalog == nil || catalog.Kind() == "none" {
		return []Coverage{coverageAbsent("files", "no package database: the static inventory cannot run")}
	}
	if len(catalog.OwnerRows()) == 0 {
		return []Coverage{coverageAbsent("files", "package file list is empty: the static inventory cannot run")}
	}
	active := activePaths(snapshot)
	var gaps []Coverage
	visited := 0
	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			break
		}
		// The pushdown every tree walk uses: a path audit does not pay for
		// the program trees the scope never names.
		if !snapshot.plan.Filter.touchesPath(root) {
			continue
		}
		info, err := os.Stat(root)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			root = filepath.Dir(root)
		}
		total := map[string]int{}
		ownedIn := map[string]int{}
		var unowned []UnownedFile
		err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if visited > inventoryBudget {
				gaps = append(gaps, coverageGap("files", "static inventory stopped at its file limit"))
				return filepath.SkipAll
			}
			visited++
			if entry.IsDir() {
				if path != root && strings.Count(strings.TrimPrefix(path, root), "/") > 2 {
					return filepath.SkipDir
				}
				return nil
			}
			dir := filepath.Dir(path)
			total[dir]++
			owned := catalog.OwnedPath(path)
			if owned {
				ownedIn[dir]++
			}
			if entry.Type()&fs.ModeSymlink != 0 || !entry.Type().IsRegular() {
				return nil
			}
			fileInfo, err := entry.Info()
			if err != nil || fileInfo.Mode().Perm()&0o111 == 0 {
				return nil
			}
			if owned || active[path] || catalog.Diversion(path) {
				return nil
			}
			unowned = append(unowned, UnownedFile{
				Path: path, Dir: dir, RootOwned: trust.Owner(fileInfo) == 0,
				Mode: fileInfo.Mode(),
			})
			return nil
		})
		if err != nil {
			gaps = append(gaps, coverageGap("files", "static inventory of "+root+": "+err.Error()))
		}
		for index := range unowned {
			unowned[index].Total = total[unowned[index].Dir]
			unowned[index].Owned = ownedIn[unowned[index].Dir]
		}
		snapshot.Unowned = append(snapshot.Unowned, unowned...)
	}
	if len(snapshot.Unowned) > 0 {
		paths := make([]string, 0, len(snapshot.Unowned))
		for _, file := range snapshot.Unowned {
			paths = append(paths, file.Path)
		}
		snapshot.ensureFacts(paths)
		sort.Slice(snapshot.Unowned, func(i, j int) bool { return snapshot.Unowned[i].Path < snapshot.Unowned[j].Path })
	}
	gaps = append(gaps, coverageComplete("files",
		"static inventory compared "+catalog.Kind()+" package file lists across "+strings.Join(roots, ", ")))
	return gaps
}

// activePaths is everything the run already judges through its own checks.
func activePaths(snapshot *Snapshot) map[string]bool {
	active := map[string]bool{}
	mark := func(path string) {
		for _, variant := range trust.UsrVariants(path) {
			active[variant] = true
		}
	}
	for _, edge := range snapshot.Activations {
		mark(edge.Trigger)
		mark(edge.Target)
	}
	for _, process := range snapshot.Processes {
		mark(process.Exe)
		mark(process.Script)
	}
	for _, path := range snapshot.Authority {
		mark(path)
	}
	return active
}

// judgeFiles is the files domain's judgment: the executables the static
// inventory found and no package owns. The view already applied the scope.
func judgeFiles(j *judgePass) []Coverage {
	for _, finding := range unownedFindings(j.snapshot, j.view.Unowned, j.a) {
		j.add(finding)
	}
	return nil
}

func unownedFindings(snapshot *Snapshot, files []UnownedFile, a *assessor) []Finding {
	var findings []Finding
	for _, file := range files {
		facts := snapshot.Facts(file.Path)
		story := a.readAuthority(facts)
		severity, reach := unownedFileSeverity(story, file.RootOwned)
		evidence := []string{
			"no package's file list records this path",
			formatSibling(file),
			"mode " + file.Mode.Perm().String() + ", owner root=" + strconv.FormatBool(file.RootOwned),
		}
		evidence = append(evidence, story.evidence...)
		title := "executable in a program directory no package owns"
		detail := "no package file list records it; the static inventory found it"
		if file.Root {
			title = "root-level executable no package owns"
			detail = "an executable at the filesystem root is an entrypoint or a dropped payload"
		}
		findings = append(findings, Finding{
			Class: "unowned-file", Severity: severity, Origin: story.origin, Reach: reach,
			Title: title, Path: file.Path, Detail: detail, Evidence: evidence,
		})
	}
	return findings
}

// unownedFileSeverity is the one ladder for an executable no package owns: a
// runtime or modified origin outranks a shipped file, and root reach
// outranks user. The static inventory and the graph walks share it.
func unownedFileSeverity(story verdict, rootOwned bool) (Severity, Reach) {
	reach := UserAsset
	if rootOwned {
		reach = RootAsset
	}
	if !story.origin.arrived() {
		if rootOwned {
			return Medium, reach
		}
		return Low, reach
	}
	if rootOwned {
		return High, reach
	}
	return Medium, reach
}

func formatSibling(file UnownedFile) string {
	if file.Root {
		return "the filesystem root is the entrypoint layer; this executable is not package-owned"
	}
	if file.Total <= 0 {
		return "the directory has no package-owned peer count"
	}
	dir := filepath.Base(file.Dir)
	if dir == "." || dir == "" {
		dir = "the directory"
	}
	return dir + ": " + strconv.Itoa(file.Owned) + " of " + strconv.Itoa(file.Total) +
		" entries are package-owned, this one is not"
}
