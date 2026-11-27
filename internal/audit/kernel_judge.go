package audit

// The kernel domain judgment: module files as artifacts, hidden state as kernel findings, and the path scoping both obey.

import (
	"fmt"
	"karma/internal/trust"
	"path/filepath"
	"strings"
)

func judgeKernel(j *judgePass) []Coverage {
	snapshot, a, filter, add := j.snapshot, j.a, j.filter, j.add
	state := &snapshot.Kernel
	if !state.Collected || len(filter.PIDs) > 0 || len(filter.Units) > 0 {
		return nil
	}
	var coverage []Coverage
	unmapped := 0
	for _, module := range state.Modules {
		if module.FileState == ModuleFileUnmapped {
			unmapped++
		}
	}
	shownUnmapped := 0
	for _, module := range state.Modules {
		if module.FileState == ModuleFileUnmapped {
			if state.MappingStale || shownUnmapped >= unmappedShown {
				continue
			}
			shownUnmapped++
		}
		judgeModule(module, a, filter, add)
	}
	if !state.MappingStale && unmapped > unmappedShown {
		coverage = append(coverage, Coverage{
			Area: "kernel", Status: CoverageDegraded, Count: unmapped - unmappedShown,
			Detail: fmt.Sprintf("%d more unmapped module(s) than the report shows", unmapped-unmappedShown),
		})
	}
	for _, module := range state.Dormant {
		judgeModule(module, a, filter, add)
	}
	for _, name := range state.RegistryGaps {
		if !filter.globalScope() {
			continue
		}
		add(Finding{
			Class: "module-registry-gap", Severity: Medium,
			Title: "module list carries a module the kernel did not register in sysfs",
			Path:  procModulesPath, Origin: Unknown, Reach: KernelAsset,
			Detail: fmt.Sprintf("module %s has no /sys/module/%s/sections entry", name, name),
			Evidence: []string{
				"the module is present in both /proc/modules reads",
				"/sys/module/" + name + "/sections is missing",
			},
		})
	}
	if filter.globalScope() {
		for _, hidden := range state.Hidden {
			add(Finding{
				Class: "hidden-module", Severity: Critical,
				Title: "kernel module hidden from /proc/modules",
				Path:  hiddenPath(hidden), Origin: Unknown, Reach: KernelAsset,
				Detail: fmt.Sprintf("module %s is carried by %s while the module list does not name it",
					hidden.Name, strings.Join(hidden.Views, " and ")),
				Evidence: []string{
					"module " + hidden.Name + " appears in " + strings.Join(hidden.Views, ", "),
					"/proc/modules did not name it in either read",
				},
			})
		}
		if finding, ok := taintFinding(state); ok {
			add(finding)
		}
		for _, pid := range state.HiddenPIDs {
			add(Finding{
				Class: "hidden-process", Severity: Critical,
				Title: "process hidden from /proc",
				Path:  fmt.Sprintf("/proc/%d", pid), Origin: Unknown, Reach: KernelAsset,
				Detail: fmt.Sprintf("pid %d is alive to the kernel and absent from /proc", pid),
				Evidence: []string{
					fmt.Sprintf("kill(%d, 0) reports the process exists", pid),
					fmt.Sprintf("/proc/%d was absent from both directory listings", pid),
				},
			})
		}
	}

	for _, dir := range state.LoaderDirs {
		if !pathOrRealInScope(dir.Path, dir.Facts.Real, filter) {
			continue
		}
		story := a.read(dir.Facts)
		evidence := []string{
			fmt.Sprintf("search directory %s: owner %d, mode %s", dir.Path, dir.Facts.Owner, dir.Facts.Mode.Perm()),
			fmt.Sprintf("origin %s (%s)", story.origin, story.why),
		}
		evidence = append(evidence, story.evidence...)
		if dir.Facts.Owner != 0 || dir.Facts.Writable {
			add(Finding{
				Class: "loader-path-writable", Severity: High,
				Title: "dynamic loader search directory writable by someone other than root",
				Path:  dir.Path, Origin: story.origin, Reach: RootAsset,
				Detail:   "a writer can replace a library every root process loads",
				Evidence: evidence,
			})
		}
	}

	var unowned []LoaderFile
	for _, file := range state.LoaderFiles {
		if pathOrRealInScope(file.Path, file.Facts.Real, filter) {
			unowned = append(unowned, file)
		}
	}
	if len(unowned) > loaderFileShown {
		coverage = append(coverage, Coverage{
			Area: "kernel", Status: CoverageDegraded, Count: len(unowned) - loaderFileShown,
			Detail: fmt.Sprintf("%d more unowned loader file(s) than the report shows", len(unowned)-loaderFileShown),
		})
		unowned = unowned[:loaderFileShown]
	}
	for _, file := range unowned {
		story := a.read(file.Facts)
		severity := Medium
		if story.origin.arrived() {
			severity = severityFor(story.origin, RootAsset)
		}
		evidence := []string{
			fmt.Sprintf("search path %s is read by every dynamic execution", filepath.Dir(file.Path)),
			fmt.Sprintf("origin %s (%s)", story.origin, story.why),
		}
		evidence = append(evidence, story.evidence...)
		add(Finding{
			Class: "loader-path-unowned", Severity: severity,
			Title: "shared library in a loader search path no package owns",
			Path:  file.Path, Origin: story.origin, Reach: RootAsset,
			Detail:   "an unowned library in a search directory can stand in for a package's soname",
			Evidence: evidence,
		})
	}

	for _, path := range state.LoaderConfig {
		facts := snapshot.Facts(path)
		if !pathOrRealInScope(path, facts.Real, filter) {
			continue
		}
		story := a.readAuthority(facts)
		evidence := []string{
			fmt.Sprintf("dynamic loader configuration %s: %s (%s)", path, story.origin, story.why),
			fmt.Sprintf("owner %d, mode %s", facts.Owner, facts.Mode.Perm()),
		}
		evidence = append(evidence, story.evidence...)
		quotes := kernelQuotes(state, path)
		if story.origin.arrived() {
			add(Finding{
				Class: "loader-config", Severity: severityFor(story.origin, RootAsset),
				Title: "dynamic loader search path changed after the artifact",
				Path:  path, Origin: story.origin, Reach: RootAsset,
				Detail: "every dynamic execution searches the directories this file names", Evidence: evidence,
				Quotes: quotes,
			})
		}
		if configReplaceable(facts) {
			add(Finding{
				Class: "loader-config-writable", Severity: writableSeverity(RootAsset),
				Title: "dynamic loader search path writable by someone other than its owner",
				Path:  path, Origin: story.origin, Reach: RootAsset,
				Detail: "a writer can add a directory every root process searches", Evidence: evidence,
				Quotes: quotes,
			})
		}
	}

	for _, path := range state.DeclarationFiles {
		facts := snapshot.Facts(path)
		if !pathOrRealInScope(path, facts.Real, filter) {
			continue
		}
		story := a.readAuthority(facts)
		evidence := []string{
			fmt.Sprintf("boot module list %s: %s (%s)", path, story.origin, story.why),
			fmt.Sprintf("owner %d, mode %s", facts.Owner, facts.Mode.Perm()),
		}
		evidence = append(evidence, story.evidence...)
		quotes := kernelQuotes(state, path)
		if story.origin.arrived() {
			add(Finding{
				Class: "module-declaration", Severity: severityFor(story.origin, RootAsset),
				Title: "boot module list changed after the artifact",
				Path:  path, Origin: story.origin, Reach: RootAsset,
				Detail: "the modules named here load at boot with kernel authority", Evidence: evidence,
				Quotes: quotes,
			})
		}
		if configReplaceable(facts) {
			add(Finding{
				Class: "module-declaration-writable", Severity: writableSeverity(RootAsset),
				Title: "boot module list writable by someone other than its owner",
				Path:  path, Origin: story.origin, Reach: RootAsset,
				Detail: "a writer can choose a module the next boot loads as root", Evidence: evidence,
				Quotes: quotes,
			})
		}
	}
	return coverage
}

// judgeModule judges one loaded module's file. A module with no file to judge
// is still a module the kernel runs; the missing and unmapped states are the
// findings.

// configReplaceable is the one writable answer for the kernel's
// configuration surfaces: the file or its holding directory can be rewritten
// by someone other than root. A user-owned directory counts — a file a
// service account owns is exactly the one that account can replace.
func configReplaceable(facts trust.Facts) bool {
	return facts.Writable || facts.ParentWritable
}

func judgeModule(module KernelModule, a *assessor, filter Filter, add func(Finding)) {
	if module.File != "" && !pathOrRealInScope(module.File, module.Facts.Real, filter) {
		return
	}
	evidence := moduleEvidence(module)
	if module.File != "" && module.Facts.Kind == trust.File && module.FileState != ModuleFileDormant {
		story := a.read(module.Facts)
		evidence = append(evidence,
			fmt.Sprintf("file %s: %s (%s)", module.File, story.origin, story.why))
		evidence = append(evidence, story.evidence...)
		switch {
		case story.origin.arrived():
			class := Class("module-introduction")
			title := "kernel module file introduced after the artifact"
			if story.origin == Modified {
				class, title = Class("module-modification"), "kernel module file changed after the artifact"
			}
			add(Finding{
				Class: class, Severity: severityFor(story.origin, KernelAsset),
				Title: title, Path: module.File, Origin: story.origin, Reach: KernelAsset,
				Detail:   fmt.Sprintf("module %s is loaded and its file is outside the artifact", module.Name),
				Evidence: evidence,
			})
			return
		case module.Facts.Writable || module.Facts.ParentOpen:
			add(Finding{
				Class: "module-writable", Severity: writableSeverity(KernelAsset),
				Title: "kernel module file writable by someone other than its owner",
				Path:  module.File, Origin: story.origin, Reach: KernelAsset,
				Detail: "a writer can replace the code the kernel runs", Evidence: evidence,
			})
			return
		case module.Facts.PackageKnown && module.Facts.Package == "":
			add(Finding{
				Class: "module-unowned", Severity: High,
				Title: "loaded kernel module's file no package owns",
				Path:  module.File, Origin: story.origin, Reach: KernelAsset,
				Detail: "the module runs in the kernel and has no distribution owner", Evidence: evidence,
			})
			return
		}
		return
	}
	switch module.FileState {
	case ModuleFileMissing:
		add(Finding{
			Class: "module-file-missing", Severity: High,
			Title: "loaded kernel module's file is missing from disk",
			Path:  module.File, Origin: Unknown, Reach: KernelAsset,
			Detail:   fmt.Sprintf("module %s is loaded; modules.dep names a file the disk does not carry", module.Name),
			Evidence: evidence,
		})
	case ModuleFileUnmapped:
		if !filter.globalScope() {
			return
		}
		add(Finding{
			Class: "module-unmapped", Severity: High,
			Title: "loaded kernel module not named by modules.dep",
			Path:  procModulesPath, Origin: Unknown, Reach: KernelAsset,
			Detail:   fmt.Sprintf("module %s is loaded and the module database names no file for it", module.Name),
			Evidence: evidence,
		})
	case ModuleFileDormant:
		if !filter.globalScope() {
			return
		}
		story := a.read(module.Facts)
		severity := Medium
		detail := "a dormant module file is a future kernel execution"
		switch {
		case story.origin.arrived():
			severity = severityFor(story.origin, KernelAsset)
			detail = "the module file was introduced or changed after the artifact"
		case module.Facts.PackageKnown && module.Facts.Package == "":
			severity = High
			detail = "the module file has no package owner and is not loaded"
			if strings.Contains(module.File, "/updates/dkms/") {
				// DKMS builds are legitimately unowned; the build path is the
				// context that keeps this a lead rather than a verdict.
				severity = Medium
				detail = "an unowned DKMS-built module; verify the DKMS registration"
			}
		case module.Facts.Writable || module.Facts.ParentOpen:
			severity = High
			detail = "a writer can change a module the next boot can load"
		default:
			return
		}
		add(Finding{
			Class: "module-dormant", Severity: severity,
			Title: "out-of-tree kernel module file outside package management",
			Path:  module.File, Origin: story.origin, Reach: KernelAsset,
			Detail: detail, Evidence: evidence,
			Trace: steps("module file "+module.File, story.origin.String(), "not loaded"),
		})
	}
}

// moduleEvidence is the registry side of one module: its flags, which views
// carry it, and the declarations that ask for it.

func moduleEvidence(module KernelModule) []string {
	lines := []string{fmt.Sprintf("module %s state %s, used by %d", module.Name, module.State, module.Used)}
	if module.Taint != "" {
		lines = append(lines, "module loader flags "+module.Taint)
	}
	var views []string
	if module.InSysfs {
		views = append(views, "sysfs")
	}
	if module.InKallsyms {
		views = append(views, "kallsyms")
	}
	if len(views) > 0 {
		lines = append(lines, "carried by "+strings.Join(views, ", "))
	}
	lines = append(lines, module.Declared...)
	return lines
}

// hiddenPath is where the operator can read the module's surviving registry
// entry.

func hiddenPath(hidden HiddenModule) string {
	for _, view := range hidden.Views {
		if view == "sysfs" {
			return filepath.Join(sysModuleDir, hidden.Name)
		}
	}
	return kallsymsPath
}

// taintFinding states the taint bits that record an operation rather than a
// stock out-of-tree module. Those bits name forced load/unload and a bad page;
// out-of-tree and unsigned are already visible on each module row.

func taintFinding(state *KernelState) (Finding, bool) {
	var flagged []string
	severity := Medium
	for bit, entry := range taintTable {
		if state.Tainted&(1<<bit) == 0 || !entry.reports {
			continue
		}
		flagged = append(flagged, entry.name)
		if entry.severity > severity {
			severity = entry.severity
		}
	}
	if len(flagged) == 0 {
		return Finding{}, false
	}
	return Finding{
		Class: "kernel-taint", Severity: severity,
		Title: "kernel taint records a forced module operation",
		Path:  taintedPath, Origin: Unknown, Reach: KernelAsset,
		Detail: fmt.Sprintf("taint mask %d: %s", state.Tainted, strings.Join(flagged, ", ")),
		Evidence: []string{
			fmt.Sprintf("kernel taint mask %d", state.Tainted),
			strings.Join(state.TaintNames, ", "),
		},
	}, true
}
