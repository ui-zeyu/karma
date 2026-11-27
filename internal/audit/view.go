package audit

// View is one run's inventories after the scope filtered them once. The audit
// report, the evidence panels and every `show` section read the same view, so
// a scope word narrows a section by the one rule the report states: a row is
// kept when the scope judges its domain and names a relation the row answers —
// a unit, a pid or a path. Activation rows also honor the selected startup
// surfaces; mounts follow a path scope through their mount point.

import (
	"karma/internal/startup"
	"karma/internal/trust"
)

type View struct {
	// Snapshot is the collected facts behind the view; the owner lookups the
	// panel rows make read the full tables, not the filtered ones.
	Snapshot *Snapshot
	Filter   Filter

	Activations []startup.Edge
	Processes   []Process
	Services    []Service
	Sockets     []Socket
	Connections []Connection
	Mounts      []Mount
	Authority   []string
	Kernel      *KernelState
	Trail       []TrailFile
	// Unowned, PackageFiles and WebFiles are the three inventories whose
	// rows are judged, not printed: the static inventory, the package-file
	// sweep and the web-root sweep. The projection and the judges read the
	// same predicate family (filter.go), so a row and its finding cannot
	// answer to two different filters.
	Unowned      []UnownedFile
	PackageFiles []PackageFile
	WebFiles     []WebFile
}

// Assessor reads origins through the snapshot's one assessor, so the panel
// rows and the judgment share the same verdicts.
func (v *View) Assessor() *assessor { return v.Snapshot.Assessor() }

// NewView applies the run's scope to the snapshot once. The projection gates
// its rows by the judged domains — these inventories are what the report
// prints — while a judge that consumes another domain's rows as context
// (network over processes, trail over processes) reads the snapshot through
// the same predicates in filter.go.
func NewView(snapshot *Snapshot, filter Filter) *View {
	view := &View{Snapshot: snapshot, Filter: filter}
	view.Activations = scopeActivations(snapshot.Activations, filter)
	view.Processes = scopeProcesses(snapshot.Processes, filter)
	view.Services = scopeServices(snapshot.Services, filter)
	view.Sockets = snapshot.Sockets
	view.Connections = snapshot.Connections
	if len(filter.Paths) > 0 || filter.hasPIDScope() || filter.hasUnitScope() {
		pids := processPIDSet(view.Processes)
		view.Sockets = socketsForPIDs(snapshot.Sockets, pids)
		view.Connections = connectionsForPIDs(snapshot.Connections, pids)
	}
	view.Authority = scopeAuthority(snapshot.Authority, filter)
	view.Mounts = scopeMounts(snapshot.Mounts, filter)
	view.Trail = scopeTrail(snapshot.Trail, view.Processes, filter)
	view.Unowned = scopeUnowned(snapshot.Unowned, filter)
	view.PackageFiles = scopePackageFiles(snapshot.Packages.Anomalies, filter)
	view.WebFiles = scopeWebFiles(snapshot.Web.Files, filter)
	if snapshot.Kernel.Collected && filter.judges(DomainKernel) {
		view.Kernel = scopeKernel(snapshot.Kernel, filter)
	}
	return view
}

// Facts reads one path's collected provenance.
func (v *View) Facts(path string) trust.Facts { return v.Snapshot.Facts(path) }

// scopeActivations keeps the activation edges the scope answers: a surface
// word narrows the surface, a unit narrows the trigger's unit, a path
// narrows either end. A pid names no activation file, so a pid scope reads
// no activation rows.
func scopeActivations(edges []startup.Edge, filter Filter) []startup.Edge {
	if !filter.judges(DomainPersistence) || len(filter.PIDs) > 0 {
		return nil
	}
	var out []startup.Edge
	for _, edge := range edges {
		if activationInScope(edge, filter) {
			out = append(out, edge)
		}
	}
	return out
}

// scopeProcesses keeps the processes the scope answers: the selected pids,
// or — under a surface, unit or path scope — the processes whose image,
// script or working directory the scope names.
func scopeProcesses(processes []Process, filter Filter) []Process {
	if !filter.judges(DomainProcesses) {
		return nil
	}
	var out []Process
	for _, process := range processes {
		if processInScope(process, filter) {
			out = append(out, process)
		}
	}
	return out
}

func processPIDSet(processes []Process) map[int]bool {
	pids := make(map[int]bool, len(processes))
	for _, process := range processes {
		pids[process.PID] = true
	}
	return pids
}

func socketsForPIDs(sockets []Socket, pids map[int]bool) []Socket {
	var out []Socket
	for _, socket := range sockets {
		if socket.PID != 0 && pids[socket.PID] {
			out = append(out, socket)
		}
	}
	return out
}

func connectionsForPIDs(connections []Connection, pids map[int]bool) []Connection {
	var out []Connection
	for _, connection := range connections {
		owners := connection.PIDs
		if len(owners) == 0 && connection.PID != 0 {
			owners = []int{connection.PID}
		}
		for _, pid := range owners {
			if pids[pid] {
				out = append(out, connection)
				break
			}
		}
	}
	return out
}

// scopeServices keeps the units the scope names. A service run answers to a
// unit word and to nothing else: a path or a pid says nothing about a unit
// inventory.
func scopeServices(services []Service, filter Filter) []Service {
	if !filter.judges(DomainServices) {
		return nil
	}
	var out []Service
	for _, service := range services {
		if unitAllowed(service.Unit, filter) {
			out = append(out, service)
		}
	}
	return out
}

// scopeConnections keeps the established relationships whose holder the
// scope names: the selected pids, or a process of a selected unit.

// scopeMounts keeps the mount rows a path scope answers: a mount under the
// selected tree, or the mount that backs the selected path. A scope that
// names no path reads the whole table; the mount table is context, not a
// verdict.
func scopeMounts(mounts []Mount, filter Filter) []Mount {
	if len(filter.Paths) == 0 {
		return mounts
	}
	var out []Mount
	for _, mount := range mounts {
		backed := false
		for _, selected := range filter.Paths {
			if trust.Under(selected, mount.Path) {
				backed = true
				break
			}
		}
		if pathInScope(mount.Path, filter) || backed {
			out = append(out, mount)
		}
	}
	return out
}

// scopeAuthority keeps the authority objects the scope answers: the
// authority domain, and a path prefix. A unit or a pid names no file,
// so they leave the walk untouched.
func scopeAuthority(paths []string, filter Filter) []string {
	if !filter.judges(DomainAuthority) {
		return nil
	}
	var out []string
	for _, path := range paths {
		if pathInScope(path, filter) {
			out = append(out, path)
		}
	}
	return out
}

// scopeTrail keeps the trail files the scope answers: a path scope names the
// file, a pid or unit scope names its owner. A surface selection that reads
// neither files nor activity leaves the trail quiet.
func scopeTrail(files []TrailFile, processes []Process, filter Filter) []TrailFile {
	if !filter.judges(DomainTrail) {
		return nil
	}
	var uids map[int]bool
	if filter.hasPIDScope() || filter.hasUnitScope() {
		uids = map[int]bool{}
		for _, process := range processes {
			if processInScope(process, filter) {
				uids[process.UID] = true
			}
		}
		if len(uids) == 0 {
			return nil
		}
	}
	var out []TrailFile
	for _, file := range files {
		if len(filter.Paths) > 0 && !pathInScope(file.Path, filter) {
			continue
		}
		if uids != nil && !uids[file.Owner] {
			continue
		}
		out = append(out, file)
	}
	return out
}

// scopeKernel keeps the kernel state the graph and JSON answers may show. A
// path scope names one module or loader tree; the global registries and pid
// space stay out, as they do in the judge.
func scopeKernel(state KernelState, filter Filter) *KernelState {
	if filter.globalScope() {
		copied := state
		return &copied
	}
	copied := state
	copied.Hidden = nil
	copied.HiddenPIDs = nil
	copied.RegistryGaps = nil
	copied.Tainted = 0
	copied.TaintNames = nil
	copied.Modules = nil
	for _, module := range state.Modules {
		if module.File != "" && pathOrRealInScope(module.File, module.Facts.Real, filter) {
			copied.Modules = append(copied.Modules, module)
		}
	}
	copied.Dormant = nil
	for _, module := range state.Dormant {
		if module.File != "" && pathOrRealInScope(module.File, module.Facts.Real, filter) {
			copied.Dormant = append(copied.Dormant, module)
		}
	}
	copied.LoaderConfig = nil
	for _, path := range state.LoaderConfig {
		if pathInScope(path, filter) {
			copied.LoaderConfig = append(copied.LoaderConfig, path)
		}
	}
	copied.DeclarationFiles = nil
	for _, path := range state.DeclarationFiles {
		if pathInScope(path, filter) {
			copied.DeclarationFiles = append(copied.DeclarationFiles, path)
		}
	}
	copied.LoaderDirs = nil
	for _, dir := range state.LoaderDirs {
		if pathOrRealInScope(dir.Path, dir.Facts.Real, filter) {
			copied.LoaderDirs = append(copied.LoaderDirs, dir)
		}
	}
	copied.LoaderFiles = nil
	for _, file := range state.LoaderFiles {
		if pathOrRealInScope(file.Path, file.Facts.Real, filter) {
			copied.LoaderFiles = append(copied.LoaderFiles, file)
		}
	}
	return &copied
}

// scopeUnowned keeps the static inventory's executables the scope answers.
// A pid or a unit names a running object, and the inventory judges files on
// disk, so those scopes leave it out — the rule the files judge applied.
func scopeUnowned(files []UnownedFile, filter Filter) []UnownedFile {
	if !filter.judges(DomainFiles) || filter.hasPIDScope() || filter.hasUnitScope() {
		return nil
	}
	var out []UnownedFile
	for _, file := range files {
		if pathInScope(file.Path, filter) {
			out = append(out, file)
		}
	}
	return out
}

// scopePackageFiles keeps the package sweep's anomalies under the path scope.
// The boundary filter stays at the judge: it compares times, not scope.
func scopePackageFiles(anomalies []PackageFile, filter Filter) []PackageFile {
	if !filter.judges(DomainPackages) {
		return nil
	}
	var out []PackageFile
	for _, anomaly := range anomalies {
		if pathInScope(anomaly.Path, filter) {
			out = append(out, anomaly)
		}
	}
	return out
}

// scopeWebFiles keeps the web sweep's scripts under the path scope. The
// origin filter stays at the judge.
func scopeWebFiles(files []WebFile, filter Filter) []WebFile {
	if !filter.judges(DomainWeb) {
		return nil
	}
	var out []WebFile
	for _, file := range files {
		if pathInScope(file.Path, filter) {
			out = append(out, file)
		}
	}
	return out
}
