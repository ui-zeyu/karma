package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"karma/internal/prov"
	"karma/internal/trust"
)

// Judge turns one snapshot into findings. The artifact boundary decides what
// arrived late; the content ledger, the activation relation and the reachable
// account decide what that means.

// classDomain is the one place a finding class is mapped to its bounded
// domain. A graph command selects findings by the domain, so a class is
// never routed by a second string table.
var classDomain = map[string]Domain{
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
	"module-missing":              DomainKernel,
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

func Judge(snapshot *Snapshot, filter Filter) *Report {
	report := &Report{
		Boundary:         snapshot.Boundary,
		Host:             snapshot.Host,
		Source:           snapshot.Source,
		Services:         snapshot.Services,
		Sockets:          snapshot.Sockets,
		Connections:      snapshot.Connections,
		Mounts:           snapshot.Mounts,
		Ledger:           snapshot.Ledger,
		Activations:      snapshot.Activations,
		ProcessRows:      snapshot.Processes,
		AuthorityObjects: snapshot.Authority,
		Unowned:          snapshot.Unowned,
		OffDomains:       filter.OffDomains,
	}
	report.snapshot = snapshot
	if len(filter.Units) > 0 {
		var services []Service
		for _, service := range snapshot.Services {
			if filter.Units[service.Unit] {
				services = append(services, service)
			}
		}
		report.Services = services
	}
	if len(filter.Units) > 0 || len(filter.PIDs) > 0 {
		report.Sockets = scopedSockets(snapshot.Sockets, snapshot.Processes, filter)
	}
	if snapshot.Kernel.Collected {
		kernel := snapshot.Kernel
		report.Kernel = &kernel
	}
	if snapshot.Boundary.Time.IsZero() {
		report.Coverage = append(report.Coverage, "no artifact boundary: origins are unknown and only structural findings remain")
	} else if snapshot.Boundary.Confidence < HighConfidence {
		report.Coverage = append(report.Coverage, fmt.Sprintf("artifact boundary from %s (%s confidence)",
			snapshot.Boundary.Source, snapshot.Boundary.Confidence))
	}
	report.Coverage = append(report.Coverage, snapshot.Coverage...)

	a := newAssessor(snapshot)
	seen := map[string]bool{}
	add := func(finding Finding) {
		finding.Domain |= classDomain[finding.Class]
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
		if len(filter.PIDs) > 0 || len(filter.Units) > 0 || !pathInScope(rows[0].Path, filter) {
			continue
		}
		if pkg == logLedgerPkg {
			evidence := []string{
				fmt.Sprintf("log changed at %s", ctimeString(rows[0].Stamp.Unix())),
				fmt.Sprintf("artifact edge %s (%s, %s)", a.boundary.Time.Format(stampLayout),
					a.boundary.Kind, a.boundary.Source),
			}
			if latest := latestPackageTime(a.times); !latest.IsZero() {
				evidence = append(evidence, fmt.Sprintf("newest recorded transaction %s", latest.Format(stampLayout)))
			}
			add(Finding{
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
		add(Finding{
			Class: "ledger-tampered", Severity: Medium, Origin: Modified, Reach: RootAsset,
			Title:    "package content ledger changed outside package management",
			Path:     rows[0].Path,
			Detail:   fmt.Sprintf("package %s: a writer with root can hide content changes from verification", pkg),
			Evidence: evidence,
		})
	}

	// Base checks first, then the registry's judges: the clock guards every
	// time comparison the modules make, and the persistence module's
	// activation loop is the spine the other domains' rows hang from.
	judgeClock(snapshot, filter, add)
	for _, module := range modules {
		if module.Judge == nil {
			continue
		}
		report.Coverage = append(report.Coverage, module.Judge(snapshot, report, a, filter, add)...)
	}

	for _, process := range snapshot.Processes {
		if process.PID == os.Getpid() || !processInScope(process, filter) {
			continue
		}
		if len(filter.Units) > 0 && !filter.Units[process.Unit] {
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

func processReach(process Process) Reach {
	uid := process.EUID
	if uid < 0 {
		uid = process.UID
	}
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

// scopedSockets keeps the listener panel on the same object the findings are
// about: the selected pids, or the pids of the selected units.
func scopedSockets(sockets []Socket, processes []Process, filter Filter) []Socket {
	pids := map[int]bool{}
	for pid := range filter.PIDs {
		pids[pid] = true
	}
	if len(filter.Units) > 0 {
		for _, process := range processes {
			if filter.Units[process.Unit] || filter.Units[templateUnit(process.Unit)] {
				pids[process.PID] = true
			}
		}
	}
	if len(pids) == 0 {
		return nil
	}
	var out []Socket
	for _, socket := range sockets {
		if pids[socket.PID] {
			out = append(out, socket)
		}
	}
	return out
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
	catalog := prov.Open(context.Background())
	boundary, packageTimes := readBoundary(catalog.Timeline())
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

// judgeAuthority states the setuid/setgid/capability surface: what it is,
// where it came from, and whether its bits sit outside the program trees.
func judgeAuthority(snapshot *Snapshot, report *Report, a *assessor, filter Filter, add func(Finding)) []string {
	if len(filter.PIDs) > 0 || len(filter.Units) > 0 {
		return nil
	}
	if filter.Surfaces != nil && !filter.Surfaces["authority"] {
		return nil
	}
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
		case story.origin == Runtime || story.origin == Modified:
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
		if (facts.Setuid || facts.Setgid || facts.Caps) && !underAny(path, trustedAuthorityRoots) {
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
