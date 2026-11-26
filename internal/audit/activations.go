package audit

// The activation relation: one trigger → mechanism → target edge per object
// the host acts by position. The judge reads the provenance of both ends; the
// weaker origin decides, and a writable end or an unowned executable target
// decides on its own. This is the persistence module's judge; the boot graph
// draws the same edges.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"karma/internal/startup"
	"karma/internal/trust"
)

// edgeQuotes cites the trigger line the activation edge was read from.
func edgeQuotes(edge startup.Edge) []Quote {
	if edge.Source == "" {
		return nil
	}
	return []Quote{{Path: edge.Trigger, Line: edge.Line, Text: edge.Source}}
}

// judgeActivations states every activation edge the filter selects: an
// introduced or modified end, a writable end, or an executable target no
// package owns.
func judgeActivations(snapshot *Snapshot, report *Report, a *assessor, filter Filter, add func(Finding)) []string {
	if len(filter.PIDs) > 0 {
		return nil
	}
	dynamic := 0
	for _, edge := range snapshot.Activations {
		if !surfaceInScope(edge.Surface, filter) || !pathInScope(edge.Trigger, filter) && !pathInScope(edge.Target, filter) {
			continue
		}
		if len(filter.Units) > 0 && !unitInScope(edge.Trigger, filter) {
			continue
		}
		if edge.Dynamic {
			dynamic++
			continue
		}
		if edge.Context {
			// A declared working directory or runtime directory is profile
			// context. One shape is a finding of its own: a unit that
			// declares write access to the root, or to a world-writable
			// directory without the sticky bit, is handing its subject a
			// file-planting ground. Everything else stays profile-only.
			if severity, ok := contextRisk(edge); ok {
				report.Activated++
				reach := edgeReach(edge)
				add(Finding{
					Class: "activation-context", Severity: severity,
					Title: "a unit's declared write access plants files",
					Path:  edge.Trigger, Origin: a.read(edge.TriggerFacts, false).origin, Reach: reach,
					Detail: fmt.Sprintf("%s in %s writes %s", edge.Mechanism, edge.Trigger, edge.Target),
					Evidence: []string{
						fmt.Sprintf("declared by %s (%s)", edge.Trigger, edge.Phase),
						fmt.Sprintf("runs as %s, reach %s", edge.Subject, reach),
					},
					Quotes: edgeQuotes(edge), Trace: edgeTrace(edge),
				})
			}
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
		detail := string(edge.Mechanism) + " in " + edge.Trigger
		evidence := []string{
			fmt.Sprintf("trigger %s: %s (%s)", edge.Trigger, triggerStory.origin, triggerStory.why),
			fmt.Sprintf("target %s: %s (%s)", edge.Target, targetStory.origin, targetStory.why),
			fmt.Sprintf("runs as %s, reach %s (%s)", edge.Subject, reach, edge.Surface),
		}
		evidence = append(evidence, triggerStory.evidence...)
		evidence = append(evidence, targetStory.evidence...)
		switch {
		case mountOverExecTree(edge):
			add(Finding{
				Class: "mount-exec-tree", Severity: High,
				Title: "network filesystem over an execution tree",
				Path:  edge.Target, Origin: origin, Reach: RootAsset,
				Detail: fmt.Sprintf("%s mounts %s (type %s)", edge.Mechanism, edge.Target, fstabType(edge.Note)),
				Evidence: append(evidence,
					"row: "+edge.Note,
					"the tree's code arrives from another host at every boot"),
				Quotes: edgeQuotes(edge), Trace: edgeTrace(edge),
			})
		case origin == Runtime || origin == Modified:
			if triggerStory.origin.Rank() <= targetStory.origin.Rank() {
				path = edge.Trigger
				detail += " activates " + edge.Target
			} else {
				detail = "activated by " + edge.Trigger + " (" + string(edge.Mechanism) + ")"
			}
			class := "activation-introduction"
			if origin == Modified {
				class = "activation-modification"
			}
			severity := severityFor(origin, reach)
			if softened && severity > Low {
				severity--
			}
			add(Finding{
				Class: class, Severity: severity, Title: titleFor(class),
				Path: path, Origin: origin, Reach: reach, Detail: detail, Evidence: evidence,
				Quotes: edgeQuotes(edge), Trace: edgeTrace(edge),
			})
		case writableEdge(edge):
			add(Finding{
				Class: "activation-writable", Severity: writableSeverity(reach),
				Title: "activation surface writable by someone other than its owner",
				Path:  edge.Trigger, Origin: triggerStory.origin, Reach: reach, Detail: detail, Evidence: evidence,
				Quotes: edgeQuotes(edge), Trace: edgeTrace(edge),
			})
		case unownedTarget(edge):
			severity := unownedSeverity(reach)
			if edge.TargetFacts.Diverted {
				// The database knows the path: dpkg-divert records a declared
				// local replacement, and the object reads one tier below a
				// file no package has ever heard of.
				severity = Medium
				evidence = append(evidence, "dpkg-divert records this path as a local replacement")
			}
			add(Finding{
				Class: "unowned-target", Severity: severity,
				Title: "activation target no package owns",
				Path:  edge.Target, Origin: targetStory.origin, Reach: reach, Detail: detail, Evidence: evidence,
				Quotes: edgeQuotes(edge), Trace: edgeTrace(edge),
			})
		}
	}
	var coverage []string
	if dynamic > 0 {
		coverage = append(coverage, fmt.Sprintf("%d activation target(s) were dynamic and could not be judged", dynamic))
	}
	return append(coverage, serviceCoverage(snapshot)...)
}

// edgeTrace is the relation a finding answers: the trigger, the mechanism and
// the target, with the nodes the boot graph draws them as.
func edgeTrace(edge startup.Edge) []Step {
	return []Step{
		{Text: edge.Trigger, Node: nodeKey("trigger", edge.Trigger)},
		{Text: string(edge.Mechanism) + " " + edge.Target, Node: nodeKey("target", edge.Target)},
	}
}

// networkFilesystems are the mount types that fetch a filesystem from another
// host: the code they deliver is decided remotely, at every boot.
var networkFilesystems = map[string]bool{
	"nfs": true, "nfs4": true, "cifs": true, "smbfs": true, "smb2": true,
	"sshfs": true, "fuse.sshfs": true, "nbd": true, "afs": true, "9p": true,
}

// execTrees are the trees a boot and every login execute from. A network
// mount over one of them hands the tree's contents to another host.
var execTrees = []string{
	"/", "/bin", "/sbin", "/lib", "/lib64", "/usr", "/usr/local", "/opt", "/etc",
}

// mountOverExecTree is the row-level shape a mount table states on its own: a
// network filesystem over an execution tree. A stock table is local, so the
// rule is quiet there; the origin judgment covers a rewritten local table.
// The root mount point is the tree itself, so it matches exactly.
func mountOverExecTree(edge startup.Edge) bool {
	if edge.Mechanism != "fstab" {
		return false
	}
	if !networkFilesystems[fstabType(edge.Note)] {
		return false
	}
	if edge.Target == "/" {
		return true
	}
	for _, tree := range execTrees[1:] {
		if trust.Under(edge.Target, tree) {
			return true
		}
	}
	return false
}

// fstabType reads the filesystem type out of a row note (the type followed by
// the options).
func fstabType(note string) string {
	fields := strings.Fields(note)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// contextRisk is the one context shape that is a finding: a ReadWritePaths
// that fences the unit in nowhere, or hands it a world-writable directory
// with no sticky bit. A sticky directory (/tmp's 1777) protects its own
// entries; a non-sticky one is a planting ground for whatever the subject's
// reach can read.
func contextRisk(edge startup.Edge) (Severity, bool) {
	if edge.Mechanism != "ReadWritePaths" {
		return Low, false
	}
	if edge.Target == "/" {
		return High, true
	}
	facts := edge.TargetFacts
	if facts.Kind == trust.Dir && facts.Writable && facts.Mode&os.ModeSticky == 0 {
		return Medium, true
	}
	return Low, false
}

func titleFor(class string) string {
	switch class {
	case "activation-introduction":
		return "runtime object in an activation surface"
	case "activation-modification":
		return "activation surface changed after the artifact"
	}
	return class
}

func edgeReach(edge startup.Edge) Reach {
	if edge.Kind == startup.Preload {
		return KernelAsset
	}
	if edge.TargetFacts.Setuid || edge.TargetFacts.Caps {
		return RootAsset
	}
	switch {
	case edge.Subject.IsRoot() || edge.Subject.Class == startup.AccountAll || edge.Subject.Class == startup.AccountLogin:
		return RootAsset
	case edge.Subject.Class == startup.AccountDynamic:
		return ServiceAsset
	}
	return UserAsset
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
	return facts.Executable || edge.Kind == startup.Preload || edge.Kind == startup.Library
}

func writableEdge(edge startup.Edge) bool {
	if edge.TriggerFacts.Writable || edge.TriggerFacts.ParentOpen ||
		edge.TargetFacts.Writable || edge.TargetFacts.ParentOpen {
		return true
	}
	if edge.Subject.IsRoot() || edge.Subject.Class == startup.AccountAll || edge.Subject.Class == startup.AccountLogin {
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

func unitInScope(trigger string, filter Filter) bool {
	if len(filter.Units) == 0 {
		return true
	}
	unit := activationUnit(trigger)
	return filter.Units[unit] || filter.Units[templateUnit(unit)]
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
