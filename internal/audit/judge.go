package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"karma/internal/startup"
	"karma/internal/trust"
)

// Judge turns one snapshot into findings. The artifact boundary decides what
// arrived late; the content ledger, the activation relation and the reachable
// account decide what that means.
func Judge(snapshot *Snapshot, filter Filter) *Report {
	report := &Report{
		Boundary: snapshot.Boundary,
		Host:     snapshot.Host,
		Source:   snapshot.Source,
		Services: snapshot.Services,
		Sockets:  snapshot.Sockets,
		Mounts:   snapshot.Mounts,
		Ledger:   snapshot.Ledger,
	}
	if snapshot.Boundary.Time.IsZero() {
		report.Coverage = append(report.Coverage, "no artifact boundary: origins are unknown and only structural findings remain")
	}
	report.Coverage = append(report.Coverage, snapshot.Coverage...)

	a := newAssessor(snapshot)
	seen := map[string]bool{}
	add := func(finding Finding) {
		if finding.Severity < filter.MinSeverity {
			return
		}
		key := finding.Class + "\x00" + finding.Path + "\x00" + finding.Detail
		if seen[key] {
			return
		}
		seen[key] = true
		report.Findings = append(report.Findings, finding)
	}

	// A tampered ledger is its own finding: the operator reads it before any
	// content-verified acquittal this run might otherwise have implied. One
	// finding per package names every ledger file that moved.
	tamperByPkg := map[string][]ledgerFile{}
	var tamperOrder []string
	for _, row := range snapshot.tamper {
		if _, seen := tamperByPkg[row.Pkg]; !seen {
			tamperOrder = append(tamperOrder, row.Pkg)
		}
		tamperByPkg[row.Pkg] = append(tamperByPkg[row.Pkg], row)
	}
	for _, pkg := range tamperOrder {
		rows := tamperByPkg[pkg]
		if len(filter.PIDs) > 0 || !pathInScope(rows[0].Path, filter) {
			continue
		}
		if pkg == logLedgerPkg {
			add(Finding{
				Class: "ledger-tampered", Severity: Medium, Origin: Modified, Reach: RootAsset,
				Title:  "package transaction log rewritten after its newest entry",
				Path:   rows[0].Path,
				Detail: "a writer can move the artifact boundary itself; every time judgment on this host rests on weaker evidence",
				Evidence: []string{
					fmt.Sprintf("log changed at %s", ctimeString(rows[0].Stamp.Unix())),
				},
			})
			continue
		}
		evidence := make([]string, 0, len(rows)+1)
		for _, row := range rows {
			evidence = append(evidence, fmt.Sprintf("ledger file %s changed at %s",
				row.Path, ctimeString(row.Stamp.Unix())))
		}
		evidence = append(evidence, fmt.Sprintf("last recorded transaction %s", a.times[pkg].Format(stampLayout)))
		add(Finding{
			Class: "ledger-tampered", Severity: Medium, Origin: Modified, Reach: RootAsset,
			Title:    "package content ledger changed after its last transaction",
			Path:     rows[0].Path,
			Detail:   fmt.Sprintf("package %s: a writer with root can hide content changes from verification", pkg),
			Evidence: evidence,
		})
	}

	processOnly := len(filter.PIDs) > 0
	dynamic := 0
	for _, edge := range snapshot.Activations {
		if processOnly {
			break
		}
		if !surfaceInScope(edge.Surface, filter) || !pathInScope(edge.Trigger, filter) && !pathInScope(edge.Target, filter) {
			continue
		}
		if edge.Dynamic {
			dynamic++
			continue
		}
		report.Activated++
		triggerStory := a.read(edge.TriggerFacts, false)
		targetStory := a.read(edge.TargetFacts, false)
		reach := edgeReach(edge)
		origin := weaker(triggerStory.origin, targetStory.origin)
		softened := targetStory.softened
		if triggerStory.origin.Rank() <= targetStory.origin.Rank() {
			softened = triggerStory.softened
		}
		path := edge.Target
		detail := edge.Mechanism + " in " + edge.Trigger
		evidence := []string{
			fmt.Sprintf("trigger %s: %s (%s)", edge.Trigger, triggerStory.origin, triggerStory.why),
			fmt.Sprintf("target %s: %s (%s)", edge.Target, targetStory.origin, targetStory.why),
			fmt.Sprintf("runs as %s, reach %s (%s)", edge.AS, reach, edge.Surface),
		}
		evidence = append(evidence, triggerStory.evidence...)
		evidence = append(evidence, targetStory.evidence...)
		switch {
		case origin == Runtime || origin == Modified:
			if triggerStory.origin.Rank() <= targetStory.origin.Rank() {
				path = edge.Trigger
				detail += " activates " + edge.Target
			} else {
				detail = "activated by " + edge.Trigger + " (" + edge.Mechanism + ")"
			}
			class := "tcb-introduction"
			if origin == Modified {
				class = "tcb-modification"
			}
			severity := severityFor(origin, reach)
			if softened && severity > Low {
				severity--
			}
			add(Finding{
				Class: class, Severity: severity, Title: titleFor(class),
				Path: path, Origin: origin, Reach: reach, Detail: detail, Evidence: evidence,
			})
		case writableEdge(edge):
			add(Finding{
				Class: "tcb-writable", Severity: writableSeverity(reach),
				Title: "activation surface writable by someone other than its owner",
				Path:  edge.Trigger, Origin: triggerStory.origin, Reach: reach, Detail: detail, Evidence: evidence,
			})
		case unownedTarget(edge):
			add(Finding{
				Class: "unowned-target", Severity: unownedSeverity(reach),
				Title: "activation target no package owns",
				Path:  edge.Target, Origin: targetStory.origin, Reach: reach, Detail: detail, Evidence: evidence,
			})
		}
	}
	if dynamic > 0 && !processOnly {
		report.Coverage = append(report.Coverage, fmt.Sprintf("%d activation target(s) were dynamic and could not be judged", dynamic))
	}
	if !processOnly {
		report.Coverage = append(report.Coverage, serviceCoverage(snapshot)...)
	}

	if !processOnly && (filter.Surfaces == nil || filter.Surfaces["authority"]) {
		for _, path := range snapshot.Authority {
			if !pathInScope(path, filter) {
				continue
			}
			report.Authority++
			facts := snapshot.Facts(path)
			story := a.read(facts, true)
			reach := authorityReach(facts)
			evidence := []string{
				fmt.Sprintf("authority object %s: %s (%s)", path, story.origin, story.why),
				fmt.Sprintf("mode %s, owner %d, setuid=%t caps=%t", facts.Mode.Perm(), facts.Owner, facts.Setuid, facts.Caps),
			}
			evidence = append(evidence, story.evidence...)
			switch {
			case story.origin == Runtime || story.origin == Modified:
				add(Finding{
					Class: "authority-object", Severity: severityFor(story.origin, reach),
					Title: "authority object introduced after the artifact",
					Path:  path, Origin: story.origin, Reach: reach, Detail: "grants authority on execution", Evidence: evidence,
				})
			case facts.Writable || facts.ParentOpen:
				add(Finding{
					Class: "authority-writable", Severity: writableSeverity(reach),
					Title: "authority object writable by someone other than its owner",
					Path:  path, Origin: story.origin, Reach: reach, Detail: "a writer can change what this object grants", Evidence: evidence,
				})
			case (facts.Setuid || facts.Caps) && facts.PackageKnown && facts.Package == "":
				add(Finding{
					Class: "authority-unowned", Severity: High, Title: "setuid or capability object no package owns",
					Path: path, Origin: story.origin, Reach: reach, Detail: "the authority has no distribution owner", Evidence: evidence,
				})
			}
		}
	}

	for _, process := range snapshot.Processes {
		if process.PID == os.Getpid() || !processInScope(process, filter) {
			continue
		}
		report.Processes++
		imageStory := a.read(process.ExeFacts, false)
		origin := imageStory.origin
		why := "image: " + imageStory.why
		softened := imageStory.softened
		contentEvidence := append([]string(nil), imageStory.evidence...)
		if process.Script != "" {
			scriptStory := a.read(process.ScriptFacts, false)
			origin = weaker(origin, scriptStory.origin)
			why = "script: " + scriptStory.why
			contentEvidence = append(contentEvidence, scriptStory.evidence...)
			softened = scriptStory.softened
			if imageStory.origin.Rank() <= scriptStory.origin.Rank() {
				softened = imageStory.softened
			}
		}
		reach := processReach(process)
		evidence := append([]string{
			fmt.Sprintf("pid %d uid %d cmdline %s", process.PID, process.UID, process.Cmdline),
		}, contentEvidence...)
		evidence = append(evidence, processContext(process)...)
		switch {
		case process.Deleted:
			// A distribution upgrade leaves old images running with their
			// files unlinked; that is a base object, not a runtime implant.
			severity := severityFor(imageStory.origin, reach)
			if severity < Low {
				severity = Low
			}
			add(Finding{
				Class: "deleted-image", Severity: severity, Title: "process runs an image deleted from disk",
				Path: process.Exe, Origin: imageStory.origin, Reach: reach,
				Detail:   fmt.Sprintf("pid %d %s", process.PID, process.Comm),
				Evidence: evidence,
			})
		case origin == Runtime || origin == Modified:
			path := process.Exe
			if process.Script != "" {
				path = process.Script
			}
			severity := severityFor(origin, reach)
			if softened && severity > Low {
				severity--
			}
			add(Finding{
				Class: "runtime-process", Severity: severity,
				Title: "running process carries runtime code",
				Path:  path, Origin: origin, Reach: reach,
				Detail: fmt.Sprintf("pid %d %s (%s)", process.PID, process.Comm, why),
				Evidence: append([]string{
					fmt.Sprintf("image %s: %s", process.Exe, imageStory.why),
				}, evidence...),
			})
		case reach >= ServiceAsset && unownedProcess(process):
			path := process.Exe
			if process.Script != "" {
				path = process.Script
			}
			add(Finding{
				Class: "unowned-process", Severity: unownedSeverity(reach),
				Title: "running process carries code no package owns",
				Path:  path, Origin: origin, Reach: reach,
				Detail:   fmt.Sprintf("pid %d %s", process.PID, process.Comm),
				Evidence: evidence,
			})
		}
	}

	report.Coverage = append(report.Coverage, ledgerCoverage(a, snapshot)...)
	for _, path := range snapshot.Unreadable {
		report.Coverage = append(report.Coverage, "unreadable activation file: "+path)
	}
	sortFindings(report.Findings)
	report.Coverage = uniqueStrings(report.Coverage)
	return report
}

// processContext names the live context of one process: its established
// connections and a chroot, the facts that turn a quiet image into a live one.
func processContext(process Process) []string {
	var lines []string
	if process.Outbound > 0 {
		lines = append(lines, fmt.Sprintf("%d established outbound connection(s)", process.Outbound))
	}
	if process.Root != "" && process.Root != "/" {
		lines = append(lines, "chrooted at "+process.Root)
	}
	return lines
}

// ledgerCoverage states how far the content evidence reached and where it
// degraded, so a quiet report can be read with its own confidence.
func ledgerCoverage(a *assessor, snapshot *Snapshot) []string {
	var lines []string
	switch snapshot.Ledger.Kind {
	case "dpkg":
	case "rpm":
		if snapshot.Ledger.Note != "" {
			lines = append(lines, snapshot.Ledger.Note)
		}
	default:
		lines = append(lines, "no package content ledger: content evidence is absent and judgments rest on time alone")
	}
	if a.remodified > 0 {
		lines = append(lines, fmt.Sprintf(
			"%d verified file(s) carry a change time after their package's last transaction (reinstalled or touched)",
			a.remodified))
	}
	if len(a.noConffile) > 0 {
		lines = append(lines, "judged conffile(s) are compared by time only, the ledger does not hash them: "+
			namesUpTo(a.noConffile, 5)+" (expected: administrators edit them)")
	}
	if len(a.noLedger) > 0 {
		lines = append(lines, "package(s) record no content hash for judged file(s): "+namesUpTo(a.noLedger, 5))
	}
	return lines
}

// namesUpTo reads a set into a sorted list, five names and a remainder.
func namesUpTo(set map[string]bool, shown int) string {
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) <= shown {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:shown], ", ") + fmt.Sprintf(", and %d more", len(names)-shown)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := values[:0]
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

// serviceCoverage names a running service whose unit the activation collector
// did not read. It is the honest answer to "systemctl shows a service the audit
// does not mention": either the unit file is outside the read layers or systemd
// started it transiently.
func serviceCoverage(snapshot *Snapshot) []string {
	if len(snapshot.Services) == 0 {
		return nil
	}
	activated := make(map[string]bool, len(snapshot.Activations))
	for _, edge := range snapshot.Activations {
		activated[activationUnit(edge.Trigger)] = true
	}
	var missing []string
	for _, service := range snapshot.Services {
		if service.Active != "active" || activated[service.Unit] || activated[templateUnit(service.Unit)] {
			continue
		}
		missing = append(missing, service.Unit)
	}
	if len(missing) == 0 {
		return nil
	}
	const shown = 10
	var lines []string
	for index, unit := range missing {
		if index == shown {
			lines = append(lines, fmt.Sprintf("... and %d more running service(s) with no activation edge", len(missing)-shown))
			break
		}
		lines = append(lines, "running service "+unit+" has no activation edge")
	}
	return lines
}

// activationUnit is the unit a trigger file belongs to: the file's own name, or
// the unit a drop-in directory belongs to.
func activationUnit(trigger string) string {
	dir := filepath.Dir(trigger)
	if strings.HasSuffix(dir, ".d") {
		return strings.TrimSuffix(filepath.Base(dir), ".d")
	}
	return filepath.Base(trigger)
}

// templateUnit maps an instance unit (getty@tty1.service) to its template
// (getty@.service), which is the file the activation collector reads.
func templateUnit(name string) string {
	at := strings.IndexByte(name, '@')
	if at < 0 {
		return name
	}
	dot := strings.IndexByte(name[at:], '.')
	if dot < 0 {
		return name
	}
	return name[:at] + "@" + name[at+dot:]
}

func titleFor(class string) string {
	switch class {
	case "tcb-introduction":
		return "runtime object in an activation surface"
	case "tcb-modification":
		return "activation surface changed after the artifact"
	}
	return class
}

func severityFor(origin Origin, reach Reach) Severity {
	switch {
	case reach >= RootAsset:
		switch origin {
		case Runtime:
			return Critical
		case Modified:
			return High
		case Unknown:
			return Medium
		}
		return Low
	case reach == ServiceAsset:
		switch origin {
		case Runtime:
			return High
		case Modified:
			return Medium
		}
		return Low
	default:
		switch origin {
		case Runtime:
			return Medium
		case Modified:
			return Low
		}
		return Info
	}
}

func writableSeverity(reach Reach) Severity {
	switch {
	case reach >= RootAsset:
		return High
	case reach == ServiceAsset:
		return Medium
	}
	return Low
}

func edgeReach(edge startup.Edge) Reach {
	if edge.Kind == startup.Preload {
		return KernelAsset
	}
	if edge.TargetFacts.Setuid || edge.TargetFacts.Caps {
		return RootAsset
	}
	switch edge.AS {
	case "root", "all", "login":
		return RootAsset
	case "dynamic":
		return ServiceAsset
	}
	return UserAsset
}

func authorityReach(facts trust.Facts) Reach {
	path := facts.Path
	switch {
	case path == "/etc/sudoers", strings.HasPrefix(path, "/etc/sudoers.d/"),
		strings.HasPrefix(path, "/etc/ssh/ssh_host_"):
		return RootAsset
	case facts.Setuid && facts.RootOwned, facts.Caps:
		return RootAsset
	case facts.RootOwned && facts.AdminLayer:
		return RootAsset
	}
	return UserAsset
}

func processReach(process Process) Reach {
	switch {
	case process.UID == 0:
		return RootAsset
	case process.UID > 0 && process.UID < 1000:
		return ServiceAsset
	case process.UID >= 1000:
		return UserAsset
	}
	return NoAsset
}

// writableEdge is the base-space invariant: an object on an activation path
// that someone other than its owner can replace.
// unownedTarget is the base-space counterpart of the origin judgment: a
// package database that answered "no package" for an executable on an
// activation path, even when the object predates the boundary.
func unownedTarget(edge startup.Edge) bool {
	facts := edge.TargetFacts
	if !facts.PackageKnown || facts.Package != "" || facts.Kind != trust.File {
		return false
	}
	return facts.Executable || edge.Kind == startup.Preload
}

func unownedProcess(process Process) bool {
	return unownedExecutable(process.ExeFacts) || unownedExecutable(process.ScriptFacts)
}

func unownedExecutable(facts trust.Facts) bool {
	return facts.PackageKnown && facts.Package == "" && facts.Kind == trust.File && facts.Executable
}

func unownedSeverity(reach Reach) Severity {
	switch {
	case reach >= RootAsset:
		return High
	case reach == ServiceAsset:
		return Medium
	}
	return Low
}

func writableEdge(edge startup.Edge) bool {
	if edge.TriggerFacts.Writable || edge.TriggerFacts.ParentOpen ||
		edge.TargetFacts.Writable || edge.TargetFacts.ParentOpen {
		return true
	}
	switch edge.AS {
	case "root", "all", "login":
		return edge.TriggerFacts.ParentWritable || edge.TargetFacts.ParentWritable
	}
	return false
}

func surfaceInScope(surface startup.Surface, filter Filter) bool {
	if filter.Surfaces == nil {
		return true
	}
	return filter.Surfaces[string(surface)] || filter.Surfaces["persistence"]
}

func pathInScope(path string, filter Filter) bool {
	if path == "" {
		return len(filter.Paths) == 0
	}
	for _, root := range filter.ExcludePaths {
		if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
			return false
		}
	}
	if len(filter.Paths) == 0 {
		return true
	}
	for _, root := range filter.Paths {
		if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func processInScope(process Process, filter Filter) bool {
	if len(filter.PIDs) > 0 {
		return filter.PIDs[process.PID]
	}
	if filter.Surfaces != nil && !filter.Surfaces["activity"] {
		return false
	}
	if len(filter.Paths) > 0 {
		return pathInScope(process.Exe, filter) || pathInScope(process.Script, filter) || pathInScope(process.Cwd, filter)
	}
	return true
}

func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		if left.Severity != right.Severity {
			return left.Severity > right.Severity
		}
		if left.Class != right.Class {
			return left.Class < right.Class
		}
		return left.Path < right.Path
	})
}

// Observer is the live watcher's view of the same boundary: one read of the
// artifact edge, then a judgment per event.
type Observer struct {
	boundary     Boundary
	packageTimes map[string]time.Time
}

// NewObserver reads the local boundary once.
func NewObserver() *Observer {
	boundary, packageTimes := readBoundary()
	return &Observer{boundary: boundary, packageTimes: packageTimes}
}

// Observe judges one image and the script an interpreter carries.
func (o *Observer) Observe(image, script trust.Facts, uid int) (Origin, Reach, Severity) {
	origin, _ := originOf(image, o.boundary, o.packageTimes)
	if script.Path != "" {
		scriptOrigin, _ := originOf(script, o.boundary, o.packageTimes)
		origin = weaker(origin, scriptOrigin)
	}
	reach := NoAsset
	switch {
	case uid == 0:
		reach = RootAsset
	case uid > 0 && uid < 1000:
		reach = ServiceAsset
	case uid >= 1000:
		reach = UserAsset
	}
	return origin, reach, severityFor(origin, reach)
}
