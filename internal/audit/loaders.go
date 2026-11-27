package audit

// The process environment is a relationship: a loader variable binds a
// process to a library the kernel will map before main(). A preload whose
// file is outside the artifact, or a library search path with the current
// directory in it, is a userland-rootkit shape that no file origin alone can
// state.

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// capabilityNames is the subset that crosses a privilege boundary by itself.
var capabilityNames = map[uint]string{
	1:  "cap_dac_override",
	2:  "cap_dac_read_search",
	6:  "cap_setgid",
	7:  "cap_setuid",
	16: "cap_sys_module",
	19: "cap_sys_ptrace",
	21: "cap_sys_admin",
	39: "cap_bpf",
}

func processCapabilities(mask uint64) []string {
	var names []string
	for bit, name := range capabilityNames {
		if mask&(1<<uint(bit)) != 0 {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// judgeLoaders states the process-to-library edges the environment declares.
func judgeLoaders(j *judgePass) {
	for _, process := range j.snapshot.Processes {
		if process.PID == selfPID() || !processInScope(process, j.filter) {
			continue
		}
		reach := processReach(process)
		for _, target := range process.LoaderTargets {
			if target.Path == "" {
				continue
			}
			evidence := []string{
				fmt.Sprintf("pid %d uid %d %s", process.PID, process.UID, process.Cmdline),
				fmt.Sprintf("%s=%s", target.Variable, target.Path),
			}
			severity := Severity(Medium)
			detail := "the process preloads a library without a service unit declaring it"
			origin := Unknown
			if filepath.IsAbs(target.Path) && target.Facts.Path != "" {
				story := j.a.read(target.Facts)
				origin = story.origin
				evidence = append(evidence, fmt.Sprintf("library %s: %s (%s)", target.Path, story.origin, story.why))
				evidence = append(evidence, story.evidence...)
				switch {
				case story.origin.arrived():
					severity = severityFor(story.origin, reach)
					detail = "the preloaded library is outside the artifact"
				case target.Facts.PackageKnown && target.Facts.Package == "":
					severity = unownedSeverity(reach)
					detail = "the preloaded library has no package owner"
				case process.Unit != "":
					// A package-owned preload on a unit-managed process is a
					// declared configuration; the unit graph already carries
					// the edge.
					continue
				}
			} else if process.Unit != "" {
				continue
			}
			j.add(Finding{
				Class: "process-preload", Severity: severity,
				Title: "process preloads a dynamic library",
				Path:  target.Path, Origin: origin, Reach: reach,
				Detail:   detail,
				Evidence: evidence,
				Trace:    steps("process "+valueOr(process.Comm, target.Path), target.Variable, "library "+target.Path),
			})
		}
		if badLibraryPath(process.LibraryPath) {
			_, interpreter := interpreterClass(process)
			packageRuntime := !interpreter && process.ExeFacts.PackageKnown && process.ExeFacts.Package != ""
			if !packageRuntime {
				severity := Medium
				if interpreter {
					severity = High
				}
				j.add(Finding{
					Class: "process-library-path", Severity: severity,
					Title: "library search path contains the current directory",
					Path:  process.Exe, Origin: Unknown, Reach: reach,
					Detail:   "LD_LIBRARY_PATH resolves a bare or current-directory component",
					Evidence: []string{fmt.Sprintf("pid %d uid %d LD_LIBRARY_PATH=%s", process.PID, process.UID, process.LibraryPath)},
					Trace:    steps("process "+valueOr(process.Comm, process.Exe), "LD_LIBRARY_PATH", "current directory"),
				})
			}
		}
		if uid := processUID(process); uid != 0 {
			if names := processCapabilities(process.CapEff); len(names) > 0 {
				j.add(Finding{
					Class: "process-capability", Severity: High,
					Title: "non-root process holds a privilege capability",
					Path:  process.Exe, Origin: Unknown, Reach: RootAsset,
					Detail:   "effective capabilities: " + strings.Join(names, ", "),
					Evidence: []string{fmt.Sprintf("pid %d euid %d cmdline %s", process.PID, uid, process.Cmdline)},
					Trace:    steps("process "+valueOr(process.Comm, process.Exe), "euid "+fmt.Sprint(uid), strings.Join(names, ", ")),
				})
			}
		}
	}
}

// badLibraryPath reports a path where the current directory can stand in for
// a library: a leading/trailing colon, an empty component, or a bare dot.
func badLibraryPath(value string) bool {
	if value == "" {
		return false
	}
	for _, component := range strings.Split(value, ":") {
		if component == "" || component == "." {
			return true
		}
	}
	return false
}
