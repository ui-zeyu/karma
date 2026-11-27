package audit

// The module collectors: the per-domain entries the registry calls. Each one
// owns the slice of the snapshot its bit describes and answers coverage, so
// the collection loop is one table walk instead of a hand-written if chain.

import (
	"context"
	"sort"
)

// collectServicesModule reads systemd's inventory, scoped to one unit when
// the plan named exactly one.
func collectServicesModule(ctx context.Context, snapshot *Snapshot) []Coverage {
	var services []Service
	var gaps []Coverage
	switch {
	case snapshot.plan.seedUnit() != "":
		services, gaps = collectServiceScoped(ctx, snapshot.plan.seedUnit())
	case len(snapshot.plan.Units) > 0:
		for unit := range snapshot.plan.Units {
			one, oneGaps := collectServiceScoped(ctx, unit)
			services = append(services, one...)
			gaps = append(gaps, oneGaps...)
		}
		sort.Slice(services, func(i, j int) bool { return services[i].Unit < services[j].Unit })
	default:
		services, gaps = collectServices(ctx)
	}
	snapshot.Services = services
	return gaps
}

// collectProcessesModule reads the running principals, scoped by the plan's
// pids, one unit or one object graph's process.
func collectProcessesModule(ctx context.Context, snapshot *Snapshot) []Coverage {
	scope := processScope{}
	if unit := snapshot.plan.seedUnit(); unit != "" {
		scope.units = map[string]bool{unit: true}
	}
	if len(snapshot.plan.Units) > 0 {
		scope.units = snapshot.plan.Units
	}
	if pid, ok := snapshot.plan.Seed.pid(); ok {
		scope.pids = map[int]bool{pid: true}
	}
	if len(snapshot.plan.PIDs) > 0 {
		scope.pids = snapshot.plan.PIDs
	}
	processes, gaps := collectProcesses(ctx, snapshot.classify, scope)
	snapshot.Processes = processes
	for _, process := range processes {
		remember(snapshot, process.Exe, process.ExeFacts)
		remember(snapshot, process.Script, process.ScriptFacts)
	}
	return gaps
}

// collectSocketsModule reads the listening surface and the established
// connections, scoped to the plan's pids or an object graph's processes.
func collectSocketsModule(ctx context.Context, snapshot *Snapshot) []Coverage {
	var scopePIDs map[int]bool
	if snapshot.plan.Seed.Kind != "" {
		scopePIDs = seedPids(snapshot.plan.Seed, snapshot.Processes)
	}
	if len(snapshot.plan.Units) > 0 {
		scopePIDs = map[int]bool{}
		for _, process := range snapshot.Processes {
			if unitMatches(process.Unit, snapshot.plan.Units) {
				scopePIDs[process.PID] = true
			}
		}
	}
	if len(snapshot.plan.PIDs) > 0 {
		scopePIDs = snapshot.plan.PIDs
	}
	sockets, connections, outbound, gaps := collectSockets(ctx, scopePIDs)
	snapshot.Sockets = sockets
	snapshot.Connections = connections
	for index := range snapshot.Processes {
		snapshot.Processes[index].Outbound = outbound[snapshot.Processes[index].PID]
	}
	return gaps
}

// collectAuthorityModule walks the authority trees and reads the facts of
// every authority object it names.
func collectAuthorityModule(ctx context.Context, snapshot *Snapshot) []Coverage {
	authority, gaps := collectAuthority(ctx, snapshot.plan.Filter)
	snapshot.Authority = authority
	for _, path := range authority {
		remember(snapshot, path, snapshot.classify(path))
	}
	return gaps
}
