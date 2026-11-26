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
	Mode      fs.FileMode
}

// collectInventory walks the plan's roots and records the executables no
// package owns. Only files outside the active judgment set are recorded: an
// activation target or a process image is already judged by its own check.
func collectInventory(ctx context.Context, snapshot *Snapshot, plan Plan) []string {
	roots := plan.InventoryRoots
	if len(roots) == 0 {
		roots = inventoryRoots
	}
	catalog := snapshot.catalog
	if catalog == nil || catalog.Kind() == "none" {
		return []string{"no package database: the static inventory cannot run"}
	}
	if len(catalog.OwnerRows()) == 0 {
		return []string{"package file list is empty: the static inventory cannot run"}
	}
	active := activePaths(snapshot)
	var gaps []string
	visited := 0
	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			break
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
				gaps = append(gaps, "static inventory stopped at its file limit")
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
			gaps = append(gaps, "static inventory of "+root+": "+err.Error())
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
	gaps = append(gaps, "static inventory compared "+catalog.Kind()+" package file lists across "+strings.Join(roots, ", "))
	return gaps
}

// activePaths is everything the run already judges through its own checks.
func activePaths(snapshot *Snapshot) map[string]bool {
	active := map[string]bool{}
	mark := func(path string) {
		if path == "" {
			return
		}
		active[path] = true
		if rest, ok := strings.CutPrefix(path, "/usr/"); ok {
			active["/"+rest] = true
		} else {
			active["/usr"+path] = true
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

func unownedFindings(snapshot *Snapshot, a *assessor, filter Filter) []Finding {
	if len(filter.PIDs) > 0 || len(filter.Units) > 0 {
		return nil
	}
	if filter.Surfaces != nil && !filter.Surfaces["files"] {
		return nil
	}
	var findings []Finding
	for _, file := range snapshot.Unowned {
		if !pathInScope(file.Path, filter) {
			continue
		}
		facts := snapshot.Facts(file.Path)
		story := a.read(facts, true)
		reach := UserAsset
		severity := Low
		if file.RootOwned {
			reach = RootAsset
			severity = Medium
		}
		if story.origin == Runtime || story.origin == Modified {
			// A file that arrived after the artifact is a live introduction;
			// an unowned file the image already carried is a lead.
			if file.RootOwned {
				severity = High
			} else {
				severity = Medium
			}
		}
		evidence := []string{
			"no package's file list records this path",
			formatSibling(file),
			"mode " + file.Mode.Perm().String() + ", owner root=" + boolWord(file.RootOwned),
		}
		evidence = append(evidence, story.evidence...)
		findings = append(findings, Finding{
			Class: "unowned-file", Severity: severity, Origin: story.origin, Reach: reach,
			Title:    "executable in a program directory no package owns",
			Path:     file.Path,
			Detail:   "no package file list records it; the static inventory found it",
			Evidence: evidence,
		})
	}
	return findings
}

func formatSibling(file UnownedFile) string {
	if file.Total <= 0 {
		return "the directory has no package-owned peer count"
	}
	return filepath.Base(file.Dir) + ": " + strconv.Itoa(file.Owned) + " of " + strconv.Itoa(file.Total) +
		" entries are package-owned, this one is not"
}

func boolWord(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
