package audit

// The kernel domain reads what the running kernel says about itself and what
// the dynamic loader searches. A loaded module is still an artifact: its .ko
// file is judged by the same origin and reach as every other object, and the
// module registries are compared because a rootkit can scrub one of them but
// rarely all three. Hidden pids are the process-side counterpart: the kernel's
// pid space is asked directly, without trusting the directory listing.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"karma/internal/localfs"
	"karma/internal/trust"
)

const (
	procModulesPath = "/proc/modules"
	kallsymsPath    = "/proc/kallsyms"
	taintedPath     = "/proc/sys/kernel/tainted"
	pidMaxPath      = "/proc/sys/kernel/pid_max"
	sysModuleDir    = "/sys/module"

	modulesDepLimit = 8 << 20
	kallsymsLimit   = 64 << 20
	configTextLimit = 256 << 10
	loaderScanLimit = 20000

	// hiddenModuleShown and hiddenPIDShown bound a report whose host is under
	// active attack; the rest is a coverage count.
	hiddenModuleShown = 50
	hiddenPIDShown    = 50
	registryGapShown  = 20
	loaderFileShown   = 50
	unmappedShown     = 20
)

// KernelModule file states: mapped names the .ko on disk, missing names a file the
// dependency database records that the disk does not carry, and unmapped
// names a loaded module modules.dep does not name at all.

const (
	ModuleFileMapped   = "mapped"
	ModuleFileMissing  = "missing"
	ModuleFileUnmapped = "unmapped"
	ModuleFileDormant  = "dormant"
)

// KernelModule is one entry of /proc/modules joined to its file and declarations.

type KernelModule struct {
	Name       string   `json:"name"`
	Size       uint64   `json:"size,omitempty"`
	Used       int      `json:"used,omitempty"`
	State      string   `json:"state,omitempty"`
	Taint      string   `json:"taint,omitempty"`
	File       string   `json:"file,omitempty"`
	FileState  string   `json:"file_state,omitempty"`
	InSysfs    bool     `json:"in_sysfs,omitempty"`
	InKallsyms bool     `json:"in_kallsyms,omitempty"`
	Declared   []string `json:"declared,omitempty"`
	// Facts are the module file's filesystem facts; they are judged through
	// the same assessor as every other artifact.
	Facts trust.Facts `json:"-"`
}

// HiddenModule is a module one registry carries while /proc/modules does not.

type HiddenModule struct {
	Name  string   `json:"name"`
	Views []string `json:"views"`
}

// LoaderDir is one directory on the dynamic loader's search path.

type LoaderDir struct {
	Path  string      `json:"path"`
	Facts trust.Facts `json:"-"`
}

// LoaderFile is one shared library inside a loader search directory. It is
// not added to the judged object set: the loader check needs ownership, and
// hashing every package library would turn a cheap graph edge into a full
// content sweep.

type LoaderFile struct {
	Path  string      `json:"path"`
	Facts trust.Facts `json:"-"`
}

// KernelState is what one kernel-domain collection answered.

type KernelState struct {
	Collected    bool           `json:"collected,omitempty"`
	Modules      []KernelModule `json:"modules,omitempty"`
	Dormant      []KernelModule `json:"dormant_modules,omitempty"`
	Hidden       []HiddenModule `json:"hidden_modules,omitempty"`
	RegistryGaps []string       `json:"registry_gaps,omitempty"`
	Tainted      int            `json:"tainted,omitempty"`
	TaintNames   []string       `json:"taint_names,omitempty"`
	// MappingStale reports a modules.dep that names none of the loaded
	// modules: the file database belongs to another kernel, so an unmapped
	// row is not evidence about one module.
	MappingStale     bool         `json:"mapping_stale,omitempty"`
	HiddenPIDs       []int        `json:"hidden_pids,omitempty"`
	DeclarationFiles []string     `json:"declaration_files,omitempty"`
	LoaderConfig     []string     `json:"loader_config,omitempty"`
	LoaderDirs       []LoaderDir  `json:"loader_dirs,omitempty"`
	LoaderFiles      []LoaderFile `json:"-"`
	// Sources are the first meaningful line of each loader or module
	// declaration file, the quote a finding carries.
	Sources map[string]Quote `json:"-"`
}

// moduleRow is one /proc/modules line before the file join.

type moduleRow struct {
	Name  string
	Size  uint64
	Used  int
	State string
	Taint string
}

// collectKernel reads the kernel domain and returns the coverage gaps its
// reads produced. The module files, declaration files and loader configuration
// join snapshot.Objects so the content ledger judges them.

func collectKernel(ctx context.Context, snapshot *Snapshot) []Coverage {
	facts := snapshot.classify
	state := &snapshot.Kernel
	if _, err := os.Stat("/proc"); err != nil {
		return []Coverage{coverageAbsent("kernel", "kernel state is only read on Linux")}
	}
	filter := snapshot.plan.Filter
	if !kernelPathNeeded(filter) {
		// The kernel state reads stay gated: they are the expensive half.
		// The loader config read is not — the search directories it names
		// are how the domain knows a library tree the scope points at, and
		// the loader walk filters its directories by the scope itself. The
		// coverage line says the state half skipped.
		gaps := []Coverage{coverageGap("kernel", "kernel state skipped: the path scope names no kernel surface")}
		return append(gaps, collectLoader(ctx, state, snapshot, facts)...)
	}
	state.Collected = true
	var gaps []Coverage

	declared, declarationFiles, declarationGaps := readModuleDeclarations(snapshot, facts)
	gaps = append(gaps, declarationGaps...)
	state.DeclarationFiles = declarationFiles

	first, firstOK := readProcModules()
	sysfsFirst, sysfsFirstOK := readSysfsModules()
	second, secondOK := readProcModules()
	// Read the cheap sysfs view on both sides of the /proc reads. The
	// intersection excludes a module that unloads during collection; the
	// union of the /proc reads excludes one that loads. The kernel symbol
	// table is expensive, so it is read once at the end and the final /proc
	// read keeps a module that appeared after the second read out of the
	// hidden set.
	sysfsSecond, sysfsSecondOK := readSysfsModules()
	var symbols map[string]bool
	var kallsymsOK bool
	if filter.globalScope() {
		var gap Coverage
		symbols, kallsymsOK, gap = readKallsymsModules(ctx)
		if gap.Detail != "" {
			gaps = append(gaps, gap)
		}
	} else {
		gaps = append(gaps, coverageGap("kernel", "hidden-module cross-check skipped: the scope names one object"))
	}
	third, thirdOK := readProcModules()
	if !firstOK && !secondOK && !thirdOK {
		gaps = append(gaps, coverageAbsent("kernel", "kernel module registry "+procModulesPath+" is unreadable"))
	}
	loaded, order, stable := mergeModuleReads(
		moduleRead{rows: first, ok: firstOK},
		moduleRead{rows: second, ok: secondOK},
		moduleRead{rows: third, ok: thirdOK},
	)
	sysfs, sysfsOK := steadyModuleView(sysfsFirst, sysfsFirstOK, sysfsSecond, sysfsSecondOK)
	if symbols != nil {
		builtin, _ := readModulesBuiltin(snapshot.Host.Kernel)
		for name := range builtin {
			delete(symbols, name)
			delete(sysfs, name)
		}
	}

	emptyContainerView := len(loaded) == 0 && snapshot.Boundary.Kind == "container" &&
		(len(sysfs) > 0 || len(symbols) > 0)
	if emptyContainerView {
		// A container runtime can mask /proc/modules while /sys and kallsyms still
		// describe the host kernel. Treating every host module as hidden would be
		// a false storm; the missing list is coverage, not a verdict.
		gaps = append(gaps, coverageGap("kernel", "module list is empty in this container; the registry cross-check was skipped"))
	} else if firstOK || secondOK || thirdOK {
		loadedNames := make(map[string]bool, len(loaded))
		for name := range loaded {
			loadedNames[name] = true
		}
		hidden, registryGaps, diffGaps := diffModuleViews(stable, loadedNames, sysfs, sysfsOK, symbols, kallsymsOK)
		state.Hidden = hidden
		state.RegistryGaps = registryGaps
		gaps = append(gaps, diffGaps...)
	}

	mapping, mapped := readModulesDep(snapshot.Host.Kernel)
	if !mapped {
		gaps = append(gaps, coverageGap("kernel", "module file mapping unavailable: "+filepath.Join("/lib/modules", snapshot.Host.Kernel, "modules.dep")))
	}
	mappedCount := 0
	for _, name := range order {
		_, ok := mapping[normalizeModuleName(name)]
		if !ok {
			continue
		}
		mappedCount++
	}
	if mapped && len(order) > 0 && mappedCount == 0 {
		state.MappingStale = true
		gaps = append(gaps, coverageGap("kernel", "module database names no loaded module: the file mapping belongs to another kernel"))
	}

	for _, name := range order {
		row := loaded[name]
		module := KernelModule{
			Name: row.Name, Size: row.Size, Used: row.Used, State: row.State, Taint: row.Taint,
			InSysfs: sysfs[name], InKallsyms: symbols[name], Declared: declared[row.Name],
		}
		if mapped {
			file, ok := mapping[normalizeModuleName(row.Name)]
			if !ok {
				module.FileState = ModuleFileUnmapped
			} else {
				module.File = file
				module.Facts = facts(file)
				if module.Facts.Kind == trust.File {
					module.FileState = ModuleFileMapped
				} else {
					module.FileState = ModuleFileMissing
				}
				remember(snapshot, file, module.Facts)
			}
		}
		state.Modules = append(state.Modules, module)
	}
	gaps = append(gaps, collectDormantModules(snapshot, state, facts)...)

	state.Tainted, state.TaintNames = readTaint()
	if state.Tainted != 0 {
		gaps = append(gaps, Coverage{
			Area: "kernel", Status: CoverageComplete,
			Detail: fmt.Sprintf("kernel taint mask %d: %s", state.Tainted, strings.Join(state.TaintNames, ", ")),
		})
	}

	if filter.globalScope() {
		hiddenPIDs, pidGaps := readHiddenPIDs(ctx)
		state.HiddenPIDs = hiddenPIDs
		gaps = append(gaps, pidGaps...)
	}

	loaderGaps := collectLoader(ctx, state, snapshot, facts)
	gaps = append(gaps, loaderGaps...)
	return gaps
}

// kernelPathNeeded reports whether a path scope can reach any kernel or
// loader object. A run scoped to /etc/passwd has no reason to read kallsyms or
// sweep a pid space.

func kernelPathNeeded(filter Filter) bool {
	if len(filter.Paths) == 0 {
		return true
	}
	roots := []string{
		"/lib/modules", "/usr/lib/modules", "/etc/modules", "/etc/modules-load.d",
		"/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/ld.so.preload",
		"/proc/modules", "/proc/kallsyms", "/sys/module",
	}
	for _, root := range roots {
		if filter.touchesPath(root) {
			return true
		}
	}
	return false
}

type moduleDeclaration struct {
	Name string
	Line int
}

func readCapped(path string, limit int64) ([]byte, error) {
	return localfs.ReadFile(path, limit)
}

// readTaint decodes the kernel taint mask. Every set bit is named; the judge
// decides which names are evidence of an operation rather than stock
// out-of-tree noise.

func readTaint() (int, []string) {
	data, err := os.ReadFile(taintedPath)
	if err != nil {
		return 0, nil
	}
	mask, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, nil
	}
	return mask, taintNames(mask)
}

// taintTable is the kernel's taint bit vocabulary. Only the bits that name a
// forced module operation produce the kernel-taint finding — a forced load
// or unload loudly, a bad page quietly — and the rest of the vocabulary
// feeds taintNames.
var taintTable = []struct {
	name     string
	reports  bool
	severity Severity
}{
	{"proprietary module", false, 0}, {"forced module load", true, High},
	{"cpu out of specification", false, 0}, {"forced module unload", true, High},
	{"machine check", false, 0}, {"bad page", true, Medium}, {"user requested", false, 0},
	{"kernel died", false, 0}, {"acpi table overridden", false, 0}, {"warning", false, 0},
	{"staging driver", false, 0}, {"firmware workaround", false, 0},
	{"out-of-tree module", false, 0}, {"unsigned module", false, 0},
	{"softlockup", false, 0}, {"livepatch", false, 0}, {"auxiliary taint", false, 0},
	{"randstruct", false, 0}, {"test taint", false, 0},
}

func taintNames(mask int) []string {
	var names []string
	for bit, entry := range taintTable {
		if mask&(1<<bit) != 0 {
			names = append(names, entry.name)
		}
	}
	return names
}
