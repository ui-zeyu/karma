package audit

import (
	"context"
	"fmt"
	"path/filepath"

	"karma/internal/fault"
	"karma/internal/prov"
	"karma/internal/startup"
	"karma/internal/trust"
)

// collectLocal reads the domains the plan selected: the startup surfaces
// through their parser, the running principals through /proc, the authority
// objects through the same filesystem facts, the program directories through
// the package inventory, and the content ledger from dpkg or rpm.
func collectLocal(ctx context.Context, plan Plan, progress Progress) (*Snapshot, error) {
	if plan.Domains == 0 {
		plan = FullPlan()
	}
	stage("catalog", progress)
	catalog := prov.Open(ctx)
	classifier := trust.NewClassifier(catalog)
	boundary, packageTimes := readBoundary(catalog.Timeline())
	facts := classifier.Classify

	stage("startup", progress)
	corpus := startup.CollectScoped(ctx, startup.OSFS{}, facts, plan.startupScope())
	var activations []startup.Edge
	analyzeErr := fault.Catch("startup analysis", func() error {
		activations = startup.Analyze(corpus)
		return nil
	})
	snapshot := &Snapshot{
		Boundary:     boundary,
		Boot:         readBootTime(),
		Host:         readHost(),
		Activations:  activations,
		Objects:      map[string]trust.Facts{},
		PackageTimes: packageTimes,
		Unreadable:   corpus.Unreadable(),
		Source:       "local",
		Clock:        readClockState(),
		catalog:      catalog,
		classifier:   classifier,
	}
	snapshot.Coverage = append(snapshot.Coverage, corpus.Gaps()...)
	if analyzeErr != nil {
		snapshot.Coverage = append(snapshot.Coverage, analyzeErr.Error())
	}
	for _, edge := range snapshot.Activations {
		remember(snapshot, edge.Trigger, edge.TriggerFacts)
		remember(snapshot, edge.Target, edge.TargetFacts)
	}
	// The registry drives collection: one walk over the modules the plan
	// selected, in the order their rows depend on each other.
	snapshot.plan = plan
	var gaps []string
	for _, module := range modules {
		if !plan.collects(module.Bit) || module.Collect == nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			gaps = append(gaps, "collection stopped: "+err.Error())
			break
		}
		stage(module.Name, progress)
		collectErr := fault.Catch("collect "+module.Name, func() error {
			gaps = append(gaps, module.Collect(ctx, snapshot)...)
			return nil
		})
		if collectErr != nil {
			gaps = append(gaps, collectErr.Error())
		}
	}
	snapshot.Coverage = append(snapshot.Coverage, gaps...)

	// An interrupted run answers with what it read: the parents and the
	// content ledger cost a second of table building and hashing, and none of
	// it should delay the operator who just pressed Ctrl-C.
	if err := ctx.Err(); err != nil {
		snapshot.Coverage = append(snapshot.Coverage, "collection stopped: "+err.Error())
		return snapshot, err
	}

	// The ancestor directories of every collected path join the judged set, so
	// the orphan story can name the owned tree a file sits in. The catalog
	// already holds the whole file list, so ownership is an index lookup.
	stage("ledger", progress)
	parents := collectParents(snapshot)
	for _, parent := range parents {
		remember(snapshot, parent, facts(parent))
	}
	attachSnapshotEvidence(ctx, snapshot)
	snapshot.Coverage = append(snapshot.Coverage, catalog.Gaps()...)
	if err := ctx.Err(); err != nil {
		snapshot.Coverage = append(snapshot.Coverage, "collection stopped: "+err.Error())
		return snapshot, err
	}
	return snapshot, nil
}

func remember(snapshot *Snapshot, path string, facts trust.Facts) {
	if path == "" || facts.Path == "" {
		return
	}
	snapshot.Objects[path] = facts
}

// stage reports the collection stage when the run carries a reporter.
func stage(name string, progress Progress) {
	if progress != nil {
		progress(name)
	}
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

// attachSnapshotEvidence gathers the content ledger through the package
// catalog: dpkg's own hashes for the judged set, a whole-system rpm -Va
// otherwise.
func attachSnapshotEvidence(ctx context.Context, snapshot *Snapshot) {
	catalog := snapshot.catalog
	evidence := evidenceSet{kind: catalog.Kind(), mounts: readMounts()}
	switch catalog.Kind() {
	case "dpkg":
		// Keep only the entries for paths this run judges. An empty judged
		// set means an empty ledger, never the whole database: a mount-only or
		// package-only run must not claim every package was checked.
		expected := dpkgExpected(catalog.Hashes(), snapshot.Objects)
		evidence.expected = expected
		evidence.entries = len(expected)
		evidence.packages = ledgerPackages(expected)
		evidence.conffiles = catalogConf(catalog, snapshot.Objects)
		evidence.rows = catalogLedgerFiles(catalog)
	case "rpm":
		evidence.rpmFlag = catalog.RPMFlags()
		evidence.rpmVerified = catalog.RPMVerified()
		evidence.packages = catalog.PackageCount()
		evidence.conffiles = catalogConf(catalog, snapshot.Objects)
		if missing := catalog.RPMMissing(); missing > 0 {
			evidence.note = fmt.Sprintf("%d packaged file(s) are missing from disk (rpm -Va)", missing)
		} else if note := catalog.RPMNote(); note != "" {
			evidence.note = note
		}
	}
	evidence.objects = snapshot.Objects
	evidence.actual = hashFiles(ctx, snapshot.Objects, evidence.expected)
	snapshot.attachEvidence(evidence)
}

// catalogConf keeps the conffile set for the paths the run judges. It is the
// answer the assessor softens on; the rest of the table is dead weight.
func catalogConf(catalog *prov.Catalog, objects map[string]trust.Facts) map[string]bool {
	out := map[string]bool{}
	for _, facts := range objects {
		for _, path := range []string{facts.Path, facts.Real} {
			if path != "" && catalog.Conffile(path) {
				out[path] = true
			}
		}
	}
	return out
}

func catalogLedgerFiles(catalog *prov.Catalog) []ledgerFile {
	rows := catalog.LedgerFiles()
	out := make([]ledgerFile, 0, len(rows))
	for _, row := range rows {
		out = append(out, ledgerFile(row))
	}
	return out
}
