package audit

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"karma/internal/fault"
	"karma/internal/prov"
	"karma/internal/trust"
)

// Judge turns one snapshot into findings. The artifact boundary decides what
// arrived late; the content ledger, the activation relation and the reachable
// account decide what that means.

// classDomain is the one place a finding class is mapped to its bounded
// domain. A graph command selects findings by the domain, so a class is
// never routed by a second string table.
var classDomain = map[Class]Domain{
	"ledger-tampered":             DomainBase,
	"clock-skew":                  DomainBase,
	"clock-boundary":              DomainBase,
	"future-timestamp":            DomainBase,
	"activation-introduction":     DomainPersistence,
	"activation-modification":     DomainPersistence,
	"activation-writable":         DomainPersistence,
	"activation-context":          DomainPersistence,
	"mount-exec-tree":             DomainPersistence,
	"unowned-target":              DomainPersistence,
	"authority-object":            DomainAuthority,
	"authority-writable":          DomainAuthority,
	"authority-unowned":           DomainAuthority,
	"authority-outside":           DomainAuthority,
	"authority-type":              DomainAuthority,
	"unowned-file":                DomainFiles,
	"runtime-process":             DomainProcesses,
	"deleted-image":               DomainProcesses,
	"unowned-process":             DomainProcesses,
	"process-preload":             DomainProcesses,
	"process-library-path":        DomainProcesses,
	"process-capability":          DomainProcesses,
	"interpreter-socket":          DomainNetwork,
	"interpreter-listener":        DomainNetwork,
	"identity-backdoor":           DomainIdentity,
	"identity-key-command":        DomainIdentity,
	"identity-factor":             DomainIdentity,
	"identity-uid0":               DomainIdentity,
	"identity-empty-password":     DomainIdentity,
	"identity-password-in-passwd": DomainIdentity,
	"identity-system-shell":       DomainIdentity,
	"identity-privileged-group":   DomainIdentity,
	"identity-sudo-nopasswd":      DomainIdentity,
	"identity-group-password":     DomainIdentity,
	"identity-sshd-keyfile":       DomainIdentity,
	"package-file-modified":       DomainPackages,
	"package-file-missing":        DomainPackages,
	"web-script":                  DomainWeb,
	"module-introduction":         DomainKernel,
	"module-modification":         DomainKernel,
	"module-unmapped":             DomainKernel,
	"module-file-missing":         DomainKernel,
	"module-unowned":              DomainKernel,
	"module-writable":             DomainKernel,
	"unit-target-missing":         DomainPersistence,
	"module-registry-gap":         DomainKernel,
	"hidden-module":               DomainKernel,
	"hidden-process":              DomainKernel,
	"kernel-taint":                DomainKernel,
	"loader-path-writable":        DomainKernel,
	"loader-path-unowned":         DomainKernel,
	"loader-config":               DomainKernel,
	"loader-config-writable":      DomainKernel,
	"module-declaration":          DomainKernel,
	"module-declaration-writable": DomainKernel,
	"module-dormant":              DomainKernel,
}

// judgePass is one judgment sweep: the collected snapshot, the scope's view
// of it, the shared assessor, the finding sink, and the two tallies the
// report's read line prints.
type judgePass struct {
	snapshot  *Snapshot
	view      *View
	a         *assessor
	filter    Filter
	add       func(Finding)
	activated int
	processes int
}

func Judge(snapshot *Snapshot, filter Filter) *Report {
	view := NewView(snapshot, filter)
	report := &Report{
		Boundary:         snapshot.Boundary,
		Host:             snapshot.Host,
		Source:           snapshot.Source,
		Services:         view.Services,
		Sockets:          view.Sockets,
		Connections:      view.Connections,
		Mounts:           view.Mounts,
		Ledger:           snapshot.Ledger,
		AuthorityObjects: view.Authority,
		Kernel:           view.Kernel,
		OffDomains:       filter.OffDomains(),
	}
	report.view = view
	if snapshot.Boundary.Time.IsZero() {
		report.Coverage = append(report.Coverage, coverageAbsent("boundary",
			"no artifact boundary: origins are unknown and only structural findings remain"))
	} else if snapshot.Boundary.Confidence < HighConfidence {
		report.Coverage = append(report.Coverage, coverageGap("boundary",
			fmt.Sprintf("artifact boundary from %s (%s confidence)",
				snapshot.Boundary.Source, snapshot.Boundary.Confidence)))
	}
	report.Coverage = append(report.Coverage, snapshot.Coverage...)

	pass := &judgePass{snapshot: snapshot, view: view, a: view.Assessor(), filter: filter}
	seen := map[string]bool{}
	pass.add = func(finding Finding) {
		finding.Domain |= classDomain[finding.Class]
		key := string(finding.Class) + "\x00" + finding.Path + "\x00" + finding.Detail
		if seen[key] {
			return
		}
		seen[key] = true
		report.Findings = append(report.Findings, finding)
	}

	// Base checks first, then the registry's judges: the ledger and clock
	// guard every content and time comparison the modules make, and the
	// persistence module's activation loop is the spine the other domains'
	// rows hang from.
	judgeBase(pass)
	for _, module := range modules {
		if module.Judge == nil || !filter.judges(module.Bit) {
			continue
		}
		judgeErr := fault.Catch("judge "+module.Name, func() error {
			report.Coverage = append(report.Coverage, module.Judge(pass)...)
			return nil
		})
		if judgeErr != nil {
			report.Coverage = append(report.Coverage, coverageAbsent(module.Name, judgeErr.Error()))
		}
	}
	report.Activated = pass.activated
	report.Processes = pass.processes

	report.Coverage = append(report.Coverage, ledgerCoverage(pass.a, snapshot)...)
	for _, path := range snapshot.Unreadable {
		report.Coverage = append(report.Coverage, coverageGap("startup", "unreadable activation file: "+path))
	}
	attachTrailEvidence(view.Trail, report)
	sortFindings(report.Findings)
	report.Coverage = uniqueCoverage(report.Coverage)
	return report
}

// judgeBase adds the two findings every run answers before the domain judges
// run: a package ledger moved after its transaction, and a clock that does not
// agree with the kernel. Both guard the comparisons the modules make.
func judgeBase(j *judgePass) {
	judgeClock(j)
	// A tampered ledger is its own finding: the operator reads it before any
	// content-verified acquittal this run might otherwise have implied. One
	// finding per package names every ledger file that moved.
	tamperByPkg := map[string][]ledgerFile{}
	var tamperOrder []string
	for _, row := range j.snapshot.tamper {
		if _, seen := tamperByPkg[row.Pkg]; !seen {
			tamperOrder = append(tamperOrder, row.Pkg)
		}
		tamperByPkg[row.Pkg] = append(tamperByPkg[row.Pkg], row)
	}
	for _, pkg := range tamperOrder {
		rows := tamperByPkg[pkg]
		if len(j.filter.PIDs) > 0 || len(j.filter.Units) > 0 || !pathInScope(rows[0].Path, j.filter) {
			continue
		}
		a := j.a
		if pkg == logLedgerPkg {
			evidence := []string{
				fmt.Sprintf("log changed at %s", ctimeString(rows[0].Stamp.Unix())),
				fmt.Sprintf("artifact edge %s (%s, %s)", a.boundary.Time.Format(stampLayout),
					a.boundary.Kind, a.boundary.Source),
			}
			if latest := latestPackageTime(a.times); !latest.IsZero() {
				evidence = append(evidence, fmt.Sprintf("newest recorded transaction %s", latest.Format(stampLayout)))
			}
			j.add(Finding{
				Class: "ledger-tampered", Severity: Medium, Origin: Modified, Reach: RootAsset,
				Title:    "package transaction log rewritten outside package management",
				Path:     rows[0].Path,
				Detail:   "a writer can move the artifact boundary itself; every time judgment on this host rests on weaker evidence",
				Evidence: evidence,
			})
			continue
		}
		evidence := make([]string, 0, len(rows)+2)
		for _, row := range rows {
			evidence = append(evidence, fmt.Sprintf("ledger file %s changed at %s",
				row.Path, ctimeString(row.Stamp.Unix())))
		}
		evidence = append(evidence, fmt.Sprintf("artifact edge %s (%s, %s)", a.boundary.Time.Format(stampLayout),
			a.boundary.Kind, a.boundary.Source))
		if stamp, known := a.times[pkg]; known {
			evidence = append(evidence, fmt.Sprintf("package's last transaction %s", stamp.Format(stampLayout)))
		}
		j.add(Finding{
			Class: "ledger-tampered", Severity: Medium, Origin: Modified, Reach: RootAsset,
			Title:    "package content ledger changed outside package management",
			Path:     rows[0].Path,
			Detail:   fmt.Sprintf("package %s: a writer with root can hide content changes from verification", pkg),
			Evidence: evidence,
		})
	}
}

// judgeProcesses turns the running principals into findings: a deleted image,
// runtime code in the image or its script, and unowned executables with
// enough reach. The loader surface (preload, library path, capabilities) is
// the process domain's other half.
func judgeProcesses(j *judgePass) []Coverage {
	a, add := j.a, j.add
	judgeLoaders(j)
	for _, process := range j.view.Processes {
		if process.PID == selfPID() {
			continue
		}
		j.processes++
		imageStory := a.read(process.ExeFacts)
		merged := imageStory
		why := "image: " + imageStory.why
		contentEvidence := append([]string(nil), imageStory.evidence...)
		if process.Script != "" {
			scriptStory := a.read(process.ScriptFacts)
			merged = imageStory.against(scriptStory)
			why = "script: " + scriptStory.why
			contentEvidence = append(contentEvidence, scriptStory.evidence...)
		}
		origin := merged.origin
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
		case origin.arrived():
			path := process.Exe
			if process.Script != "" {
				path = process.Script
			}
			severity := merged.soften(severityFor(origin, reach))
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
	return nil
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
	if process.Seccomp > 0 {
		lines = append(lines, fmt.Sprintf("seccomp mode %d", process.Seccomp))
	}
	if process.NoNewPrivs {
		lines = append(lines, "no_new_privs set")
	}
	return lines
}

// ledgerCoverage states how far the content evidence reached and where it
// degraded, so a quiet report can be read with its own confidence.
func ledgerCoverage(a *assessor, snapshot *Snapshot) []Coverage {
	var records []Coverage
	if note := snapshot.Ledger.Note; note != "" {
		records = append(records, coverageGap("ledger", note))
	}
	switch snapshot.Ledger.Kind {
	case "dpkg":
	case "rpm":
	default:
		records = append(records, coverageAbsent("ledger",
			"no package content ledger: content evidence is absent and judgments rest on time alone"))
	}
	if len(a.remodifiedSet) > 0 {
		records = append(records, Coverage{Area: "ledger", Status: CoverageDegraded, Count: len(a.remodifiedSet),
			Detail: fmt.Sprintf(
				"%d verified file(s) carry a change time after their package's last transaction (reinstalled or touched)",
				len(a.remodifiedSet))})
	}
	if len(a.noConffile) > 0 {
		records = append(records, Coverage{Area: "ledger", Status: CoverageDegraded, Count: len(a.noConffile),
			Detail: "judged conffile(s) are compared by time only, the ledger does not hash them: " +
				namesUpTo(a.noConffile, 5) + " (expected: administrators edit them)"})
	}
	if len(a.unreadable) > 0 {
		records = append(records, Coverage{Area: "ledger", Status: CoverageDegraded, Count: len(a.unreadable),
			Detail: "content comparison could not read judged file(s), they are compared by time only: " +
				namesUpTo(a.unreadable, 5)})
	}
	if len(a.noLedger) > 0 {
		records = append(records, Coverage{Area: "ledger", Status: CoverageDegraded, Count: len(a.noLedger),
			Detail: "package(s) record no content hash for judged file(s): " + namesUpTo(a.noLedger, 5)})
	}
	return records
}

// namesUpTo reads a set into a sorted list, five names and a remainder.
func namesUpTo[V any](set map[string]V, shown int) string {
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	slices.Sort(names)
	if len(names) <= shown {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:shown], ", ") + fmt.Sprintf(", and %d more", len(names)-shown)
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

func authorityReach(facts trust.Facts) Reach {
	path := facts.Path
	switch {
	case path == "/etc/sudoers", strings.HasPrefix(path, "/etc/sudoers.d/"),
		strings.HasPrefix(path, "/etc/ssh/ssh_host_"):
		return RootAsset
	case facts.Setuid && facts.RootOwned, facts.Caps:
		return RootAsset
	case facts.Setgid && facts.Group == 0:
		return RootAsset
	case facts.Setgid:
		return ServiceAsset
	case facts.RootOwned && facts.AdminLayer:
		return RootAsset
	}
	return UserAsset
}

func processUID(process Process) int {
	if process.EUID >= 0 {
		return process.EUID
	}
	return process.UID
}

// reachForUID is the one uid-to-asset ladder: the audit's processReach and
// the watcher's Observe answer from the same table, so the service-account
// threshold cannot drift between the two products.
func reachForUID(uid int) Reach {
	switch {
	case uid == 0:
		return RootAsset
	case uid > 0 && uid < 1000:
		return ServiceAsset
	case uid >= 1000:
		return UserAsset
	}
	return NoAsset
}

func processReach(process Process) Reach {
	return reachForUID(processUID(process))
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

// sortFindings orders the report for reading: severity first, then the
// object, then the class and title. The last key is part of the panel's
// grouping key, so equal group keys stay adjacent and one run becomes one
// panel.
func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		if left.Severity != right.Severity {
			return left.Severity > right.Severity
		}
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		if left.Class != right.Class {
			return left.Class < right.Class
		}
		return left.Title < right.Title
	})
}

// Observer is the live watcher's view of the same boundary: one read of the
// artifact edge, then a judgment per event.
type Observer struct {
	boundary     Boundary
	packageTimes map[string]time.Time
}

// NewObserverWith reuses the caller's catalog, so the watcher does not open a
// second package database beside the one its facts already use.
func NewObserverWith(catalog *prov.Catalog) *Observer {
	if catalog == nil {
		return &Observer{}
	}
	packageTimes := catalog.Timeline()
	boundary := readBoundary(packageTimes)
	return &Observer{boundary: boundary, packageTimes: packageTimes}
}

// Observe judges one image and the script an interpreter carries.
func (o *Observer) Observe(image, script trust.Facts, uid int) (Origin, Reach, Severity) {
	origin, _ := originOf(image, o.boundary, o.packageTimes)
	if script.Path != "" {
		scriptOrigin, _ := originOf(script, o.boundary, o.packageTimes)
		origin = weaker(origin, scriptOrigin)
	}
	reach := reachForUID(uid)
	return origin, reach, severityFor(origin, reach)
}

// judgeAuthority states the setuid/setgid/capability surface: what it is,
// where it came from, and whether its bits sit outside the program trees.
func judgeAuthority(j *judgePass) []Coverage {
	snapshot, a, filter, add := j.snapshot, j.a, j.filter, j.add
	if len(filter.PIDs) > 0 || len(filter.Units) > 0 {
		return nil
	}
	for _, path := range snapshot.Authority {
		if !pathInScope(path, filter) {
			continue
		}
		facts := snapshot.Facts(path)
		story := a.readAuthority(facts)
		reach := authorityReach(facts)
		evidence := []string{
			fmt.Sprintf("authority object %s: %s (%s)", path, story.origin, story.why),
			fmt.Sprintf("mode %s, owner %d, group %d, setuid=%t setgid=%t caps=%t",
				facts.Mode.Perm(), facts.Owner, facts.Group, facts.Setuid, facts.Setgid, facts.Caps),
		}
		evidence = append(evidence, story.evidence...)
		hasBits := facts.Setuid || facts.Setgid || facts.Caps
		outside, reason := false, ""
		if hasBits {
			outside, reason = unusualAuthorityBinary(path, facts)
			if outside {
				evidence = append(evidence, reason)
			}
		}
		switch {
		case story.origin.arrived():
			add(Finding{
				Class: "authority-object", Severity: severityFor(story.origin, reach),
				Title: "authority object introduced after the artifact",
				Path:  path, Origin: story.origin, Reach: reach, Detail: "grants authority on execution", Evidence: evidence,
				Trace: steps("artifact boundary", path, authorityBit(facts)),
			})
		case facts.Writable || facts.ParentOpen:
			add(Finding{
				Class: "authority-writable", Severity: writableSeverity(reach),
				Title: "authority object writable by someone other than its owner",
				Path:  path, Origin: story.origin, Reach: reach, Detail: "a writer can change what this object grants", Evidence: evidence,
				Trace: steps(path, "writable", authorityBit(facts)),
			})
		case (facts.Setuid || facts.Setgid || facts.Caps) && facts.PackageKnown && facts.Package == "":
			severity := High
			if facts.Diverted {
				// The database knows the path: dpkg-divert records a declared
				// local replacement, and the object reads one tier below a
				// file no package has ever heard of.
				severity = Medium
				evidence = append(evidence, "dpkg-divert records this path as a local replacement")
			}
			add(Finding{
				Class: "authority-unowned", Severity: severity, Title: "setuid, setgid or capability object no package owns",
				Path: path, Origin: story.origin, Reach: reach, Detail: "the authority has no distribution owner", Evidence: evidence,
				Trace: steps(path, "no package", authorityBit(facts)),
			})
		}
		if (facts.Setuid || facts.Setgid || facts.Caps) && !trust.UnderAny(path, programTrees) {
			severity := High
			if facts.Setgid && !facts.Setuid && !facts.Caps {
				severity = Medium
			}
			if severity == High && facts.PackageKnown && facts.Package != "" {
				// A package's own object in an administrator tree is a
				// declared install — third-party setuid tools land here — and
				// reads one tier below a file the database has never heard of.
				severity = Medium
			}
			if facts.PackageKnown && facts.Package != "" {
				evidence = append(evidence, "package "+facts.Package+" installs it outside the program trees")
			}
			add(Finding{
				Class: "authority-outside", Severity: severity,
				Title: "authority object outside the distribution's program trees",
				Path:  path, Origin: story.origin, Reach: reach,
				Detail:   "an authority bit in an administrator or data tree is a planted backdoor shape",
				Evidence: evidence,
				Trace:    steps(path, "outside trusted program trees", authorityBit(facts)),
			})
		}
		if hasBits && outside {
			add(Finding{
				Class: "authority-type", Severity: High,
				Title: "authority object is not a normal ELF execution",
				Path:  path, Origin: story.origin, Reach: reach,
				Detail: reason, Evidence: evidence,
				Trace: steps(path, reason),
			})
		}
	}
	return nil
}
