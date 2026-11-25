package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"karma/internal/startup"
	"karma/internal/trust"
)

// collectLocal reads the target in process: the activation surfaces through
// their parser, the running principals through /proc, the authority objects
// through the same filesystem facts, and the content ledger from dpkg or rpm.
func collectLocal(ctx context.Context) (*Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	boundary, packageTimes := readBoundary()
	resolver := trust.NewResolver()
	facts := func(path string) trust.Facts { return trust.Classify(path, resolver) }

	corpus := startup.Collect(startup.OSFS{}, facts)
	corpus.Prefetch(resolver.OwnedAll)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	snapshot := &Snapshot{
		Boundary:     boundary,
		Host:         readHost(),
		Activations:  startup.Analyze(corpus),
		Objects:      map[string]trust.Facts{},
		PackageTimes: packageTimes,
		Unreadable:   corpus.Unreadable(),
		Source:       "local",
	}
	for _, edge := range snapshot.Activations {
		remember(snapshot, edge.Trigger, edge.TriggerFacts)
		remember(snapshot, edge.Target, edge.TargetFacts)
	}
	processes, gaps := collectProcesses(ctx, facts)
	snapshot.Processes = processes
	services, serviceGaps := collectServices(ctx)
	snapshot.Services = services
	sockets, outbound, socketGaps := collectSockets(ctx)
	snapshot.Sockets = sockets
	for index := range snapshot.Processes {
		snapshot.Processes[index].Outbound = outbound[snapshot.Processes[index].PID]
	}
	snapshot.Coverage = append(snapshot.Coverage, serviceGaps...)
	snapshot.Coverage = append(snapshot.Coverage, socketGaps...)
	for _, process := range processes {
		remember(snapshot, process.Exe, process.ExeFacts)
		remember(snapshot, process.Script, process.ScriptFacts)
	}
	authority, authorityGaps := collectAuthority(ctx)
	snapshot.Authority = authority
	for _, path := range authority {
		remember(snapshot, path, facts(path))
	}
	snapshot.Coverage = append(snapshot.Coverage, gaps...)
	snapshot.Coverage = append(snapshot.Coverage, authorityGaps...)

	// The ancestor directories of every collected path join the judged set, so
	// the orphan story can name the owned tree a file sits in. Their ownership
	// is answered in one batched package query before the facts are read.
	parents := collectParents(snapshot)
	resolver.OwnedAll(parents)
	for _, parent := range parents {
		remember(snapshot, parent, facts(parent))
	}
	attachSnapshotEvidence(ctx, snapshot)
	if snapshot.Boundary.Confidence < HighConfidence {
		snapshot.Coverage = append(snapshot.Coverage,
			fmt.Sprintf("artifact boundary from %s (%s confidence)",
				snapshot.Boundary.Source, snapshot.Boundary.Confidence))
	}
	return snapshot, nil
}

func remember(snapshot *Snapshot, path string, facts trust.Facts) {
	if path == "" || facts.Path == "" {
		return
	}
	snapshot.Objects[path] = facts
}

// collectParents answers the ancestor directories of every collected path,
// excluding the root itself. The caller resolves their ownership before the
// facts are read, so one batched package query covers them all.
func collectParents(snapshot *Snapshot) []string {
	seen := map[string]bool{}
	var parents []string
	for path := range snapshot.Objects {
		for dir := filepath.Dir(path); dir != "/" && dir != "." && !seen[dir]; dir = filepath.Dir(dir) {
			seen[dir] = true
			parents = append(parents, dir)
		}
	}
	return parents
}

// attachSnapshotEvidence gathers the content ledger: dpkg's own files when the
// target is a dpkg host, a whole-system rpm -Va otherwise.
func attachSnapshotEvidence(ctx context.Context, snapshot *Snapshot) {
	evidence := evidenceSet{kind: "none", mounts: readMounts()}
	if expected, conffiles, rows, ok := readDpkgLedger(ctx, dpkgInfoDir, candidatePackages(snapshot.Objects)); ok {
		evidence.kind = "dpkg"
		// Keep only the entries for paths this run judges, the same answer
		// the sh collector ships: the summary reads as coverage of the judged
		// set, not of the whole ledger.
		candidateKeys := map[string]bool{}
		for _, facts := range snapshot.Objects {
			if facts.Kind != trust.File || facts.Real == "" {
				continue
			}
			for _, key := range usrKeys(facts.Real) {
				candidateKeys[key] = true
			}
		}
		for key := range expected {
			if !candidateKeys[key] {
				delete(expected, key)
			}
		}
		evidence.expected = expected
		evidence.conffiles = conffiles
		evidence.rows = rows
		if stamp, _, statOk := trust.StatMeta(packageLog); statOk {
			if row, tampered := packageLogTamper(snapshot.PackageTimes, time.Unix(stamp, 0), medianStamp(rows)); tampered {
				evidence.rows = append(evidence.rows, row)
			}
		}
	} else if rpmBinary() != "" {
		evidence.kind = "rpm"
		var missing int
		evidence.rpmFlag, evidence.conffiles, missing, evidence.note = readRpmVerify(ctx)
		if missing > 0 {
			evidence.note = fmt.Sprintf("%d packaged file(s) are missing from disk (rpm -Va)", missing)
		}
		evidence.times = readRpmTimeline(ctx)
	}
	evidence.actual = hashFiles(ctx, snapshot.Objects)
	snapshot.attachEvidence(evidence)
}
