package audit

// View is one run's inventories after the scope filtered them once. The audit
// report, the evidence panels and every `show` section read the same view, so
// a scope word narrows a section by the one rule the report states: a row is
// kept when the scope names a relation the row answers — a unit, a pid, a
// path, or one of the surface words the judgment shares.

import (
	"karma/internal/startup"
	"karma/internal/trust"
)

type View struct {
	// Snapshot is the collected facts behind the view; the owner lookups the
	// panel rows make read the full tables, not the filtered ones.
	Snapshot *Snapshot
	Filter   Filter

	assessor *assessor

	Activations []startup.Edge
	Processes   []Process
	Services    []Service
	Sockets     []Socket
	Connections []Connection
	Mounts      []Mount
	Authority   []string
	Kernel      *KernelState
}

// NewView applies the run's scope to the snapshot once. The judges keep their
// own reading of the snapshot — a finding's scope is judgment policy — while
// every printed inventory comes from here.
func NewView(snapshot *Snapshot, filter Filter) *View {
	view := &View{Snapshot: snapshot, Filter: filter, assessor: newAssessor(snapshot)}
	view.Activations = scopeActivations(snapshot.Activations, filter)
	view.Processes = scopeProcesses(snapshot.Processes, filter)
	view.Services = scopeServices(snapshot.Services, filter)
	view.Sockets = snapshot.Sockets
	view.Connections = snapshot.Connections
	if len(filter.Units) > 0 || len(filter.PIDs) > 0 {
		view.Sockets = scopedSockets(snapshot.Sockets, snapshot.Processes, filter)
		view.Connections = scopeConnections(snapshot.Connections, snapshot.Processes, filter)
	}
	view.Authority = scopeAuthority(snapshot.Authority, filter)
	view.Mounts = snapshot.Mounts
	if snapshot.Kernel.Collected {
		kernel := snapshot.Kernel
		view.Kernel = &kernel
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
	if len(filter.PIDs) > 0 {
		return nil
	}
	var out []startup.Edge
	for _, edge := range edges {
		if !surfaceInScope(edge.Surface, filter) || !unitInScope(edge.Trigger, filter) {
			continue
		}
		if len(filter.Paths) > 0 && !pathInScope(edge.Trigger, filter) && !pathInScope(edge.Target, filter) {
			continue
		}
		out = append(out, edge)
	}
	return out
}

// scopeProcesses keeps the processes the scope answers: the selected pids,
// or — under a surface, unit or path scope — the processes whose image,
// script or working directory the scope names.
func scopeProcesses(processes []Process, filter Filter) []Process {
	var out []Process
	for _, process := range processes {
		if len(filter.PIDs) > 0 {
			if filter.PIDs[process.PID] {
				out = append(out, process)
			}
			continue
		}
		if filter.Surfaces != nil && !filter.Surfaces["activity"] {
			continue
		}
		if len(filter.Units) > 0 && !filter.Units[process.Unit] && !filter.Units[templateUnit(process.Unit)] {
			continue
		}
		if len(filter.Paths) > 0 && !pathInScope(process.Exe, filter) && !pathInScope(process.Script, filter) && !pathInScope(process.Cwd, filter) {
			continue
		}
		out = append(out, process)
	}
	return out
}

// scopeServices keeps the units the scope names. A service run answers to a
// unit word and to nothing else: a path or a pid says nothing about a unit
// inventory.
func scopeServices(services []Service, filter Filter) []Service {
	if len(filter.Units) == 0 {
		return services
	}
	var out []Service
	for _, service := range services {
		if filter.Units[service.Unit] || filter.Units[templateUnit(service.Unit)] {
			out = append(out, service)
		}
	}
	return out
}

// scopeConnections keeps the established relationships whose holder the
// scope names: the selected pids, or a process of a selected unit.
func scopeConnections(connections []Connection, processes []Process, filter Filter) []Connection {
	if len(filter.Units) == 0 && len(filter.PIDs) == 0 {
		return connections
	}
	pids := map[int]bool{}
	for pid := range filter.PIDs {
		pids[pid] = true
	}
	for _, process := range processes {
		if filter.Units[process.Unit] || filter.Units[templateUnit(process.Unit)] {
			pids[process.PID] = true
		}
	}
	var out []Connection
	for _, connection := range connections {
		if connection.PID != 0 && pids[connection.PID] {
			out = append(out, connection)
			continue
		}
		for _, pid := range connection.PIDs {
			if pids[pid] {
				out = append(out, connection)
				break
			}
		}
	}
	return out
}

// scopeAuthority keeps the authority objects the scope answers: the
// authority surface word, and a path prefix. A unit or a pid names no file,
// so they leave the walk untouched.
func scopeAuthority(paths []string, filter Filter) []string {
	if filter.Surfaces != nil && !filter.Surfaces["authority"] {
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
