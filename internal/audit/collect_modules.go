package audit

// The module collectors: the per-domain entries the registry calls. Each one
// owns the slice of the snapshot its bit describes and answers coverage, so
// the collection loop is one table walk instead of a hand-written if chain.

import (
	"context"
	"strconv"
)

// collectServicesModule reads systemd's inventory, scoped to one unit when
// the plan named exactly one.
func collectServicesModule(ctx context.Context, snapshot *Snapshot) []string {
	var services []Service
	var gaps []string
	switch {
	case snapshot.plan.seedUnit() != "":
		services, gaps = collectServiceScoped(ctx, snapshot.plan.seedUnit())
	case len(snapshot.plan.Units) == 1:
		for unit := range snapshot.plan.Units {
			services, gaps = collectServiceScoped(ctx, unit)
		}
	default:
		services, gaps = collectServices(ctx)
	}
	snapshot.Services = services
	return gaps
}

// collectProcessesModule reads the running principals, scoped by the plan's
// pids, one unit or one object graph's process.
func collectProcessesModule(ctx context.Context, snapshot *Snapshot) []string {
	scope := processScope{unit: snapshot.plan.seedUnit()}
	if snapshot.plan.Seed.Kind == "pid" {
		if pid, err := strconv.Atoi(snapshot.plan.Seed.Value); err == nil {
			scope.pids = map[int]bool{pid: true}
		}
	}
	if pids := positivePIDs(snapshot.plan.PIDs); pids != nil {
		scope.pids = pids
	}
	processes, gaps := collectProcesses(ctx, snapshot.classify, snapshot.catalog.OwnedAll, scope)
	snapshot.Processes = processes
	for _, process := range processes {
		remember(snapshot, process.Exe, process.ExeFacts)
		remember(snapshot, process.Script, process.ScriptFacts)
	}
	return gaps
}

// collectSocketsModule reads the listening surface and the established
// connections, scoped to the plan's pids or an object graph's processes.
func collectSocketsModule(ctx context.Context, snapshot *Snapshot) []string {
	var scopePIDs map[int]bool
	if snapshot.plan.Seed.Kind != "" {
		scopePIDs = seedPids(snapshot.plan.Seed, snapshot.Processes)
	}
	if pids := positivePIDs(snapshot.plan.PIDs); pids != nil {
		scopePIDs = pids
	}
	var sockets []Socket
	var connections []Connection
	var outbound map[int]int
	var gaps []string
	if scopePIDs != nil {
		sockets, connections, outbound, gaps = collectSocketsScoped(ctx, scopePIDs)
	} else {
		sockets, connections, outbound, gaps = collectSockets(ctx)
	}
	snapshot.Sockets = sockets
	snapshot.Connections = connections
	for index := range snapshot.Processes {
		snapshot.Processes[index].Outbound = outbound[snapshot.Processes[index].PID]
	}
	return gaps
}

// collectAuthorityModule walks the authority trees and reads the facts of
// every authority object it names.
func collectAuthorityModule(ctx context.Context, snapshot *Snapshot) []string {
	authority, gaps := collectAuthority(ctx)
	snapshot.Authority = authority
	for _, path := range authority {
		remember(snapshot, path, snapshot.classify(path))
	}
	return gaps
}
