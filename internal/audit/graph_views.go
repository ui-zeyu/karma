package audit

// Domain graphs are the picture behind the findings. The audit states one
// broken relation; the graph shows the objects that touch it, so an operator
// reads a chain instead of a file dump. The builders read the same typed
// snapshot state the judges read; AttachFindings selects findings by the
// domain each judge stamped on them.

import (
	"fmt"
	"strconv"
	"strings"
)

// domainRoot builds the root node one domain graph hangs from. The root is
// the page's spine, so it is context: no origin, no unknown marker.
func domainRoot(kind, name, detail string, reach Reach) *GraphBuilder {
	return NewGraphBuilder(&GraphNode{
		ID: nodeKey(kind, name), Kind: kind, Name: name,
		Reach: reach.String(), Detail: detail, Context: true,
	})
}

// networkGraph is process -> socket -> peer, with each process's image and
// origin on the node.
func networkGraph(snapshot *Snapshot) *GraphView {
	graph := domainRoot("domain", "network", "processes, listeners and established peers", NoAsset)
	a := newAssessor(snapshot)
	byListener := map[int][]Socket{}
	byConnection := map[int][]Connection{}
	for _, socket := range snapshot.Sockets {
		if socket.PID != 0 {
			byListener[socket.PID] = append(byListener[socket.PID], socket)
		}
	}
	for _, connection := range snapshot.Connections {
		owners := connection.PIDs
		if len(owners) == 0 {
			owners = []int{connection.PID}
		}
		for _, pid := range owners {
			byConnection[pid] = append(byConnection[pid], connection)
		}
	}
	for _, process := range snapshot.Processes {
		listeners, connections := byListener[process.PID], byConnection[process.PID]
		if len(listeners) == 0 && len(connections) == 0 {
			continue
		}
		story := a.read(process.ExeFacts, false)
		name := valueOr(process.Comm, strconv.Itoa(process.PID))
		node := graph.Node("process", strconv.Itoa(process.PID), name, process.Exe,
			story.origin, processReach(process),
			fmt.Sprintf("pid %d uid %d", process.PID, process.UID))
		graph.link(graph.root, node.ID, "observed", "kernel", "high", "")
		for _, socket := range listeners {
			s := graph.Node("socket", socket.Proto+" "+socket.Local, socket.Proto+" "+socket.Local, "",
				Unknown, NoAsset, fmt.Sprintf("listening, pid %d", socket.PID))
			graph.link(node.ID, s.ID, "listens", "kernel", "high", "")
		}
		for _, connection := range connections {
			id := connection.Proto + " " + connection.Local + " → " + connection.Peer
			s := graph.Node("socket", id, id, "", Unknown, NoAsset,
				fmt.Sprintf("established, pid %d", connection.PID))
			graph.link(node.ID, s.ID, "connects", "kernel", "high", connection.Peer)
			peer := graph.Node("peer", connection.Peer, connection.Peer, "", Unknown, NoAsset, "established peer")
			graph.link(s.ID, peer.ID, "peer", "kernel", "high", "")
		}
	}
	return graph.GraphView("domain", snapshot)
}

// packageGraph is package -> broken file edge.
func packageGraph(snapshot *Snapshot) *GraphView {
	graph := domainRoot("domain", "packages",
		fmt.Sprintf("%d packages · %d files · %d anomalies",
			snapshot.Packages.Packages, snapshot.Packages.Files, len(snapshot.Packages.Anomalies)),
		NoAsset)
	for _, anomaly := range snapshot.Packages.Anomalies {
		pkg := graph.Node("package", anomaly.Package, anomaly.Package, "", Unknown, RootAsset,
			"package transaction "+anomaly.Transaction.Format(stampLayout))
		graph.link(graph.root, pkg.ID, "contains", "package", "high", "")
		origin := Modified
		detail := "changed after the transaction"
		missing := false
		if anomaly.Missing {
			origin = Unknown
			detail = "missing from disk"
			missing = true
		}
		file := graph.Node("file", anomaly.Path, anomaly.Path, anomaly.Path, origin,
			packageFileReach(anomaly.Path), detail)
		file.Missing = missing
		graph.link(pkg.ID, file.ID, "owns", "package", "high",
			fmt.Sprintf("ctime %s · transaction %s", ctimeString(anomaly.CTime), anomaly.Transaction.Format(stampLayout)))
	}
	return graph.GraphView("domain", snapshot)
}

// kernelGraph is module -> file/registry state.
func kernelGraph(snapshot *Snapshot) *GraphView {
	graph := domainRoot("domain", "kernel", "module registries, taint and hidden pids", KernelAsset)
	a := newAssessor(snapshot)
	for _, module := range snapshot.Kernel.Modules {
		story := a.read(module.Facts, false)
		detail := fmt.Sprintf("%s used %d", valueOr(module.State, "loaded"), module.Used)
		if module.Taint != "" {
			detail += " · loader flags " + module.Taint
		}
		key := module.Name
		if module.File != "" {
			key = module.File
		}
		node := graph.Node("module", key, module.Name, module.File, story.origin, KernelAsset, detail)
		if module.FileState == ModuleFileMissing {
			node.Missing = true
		}
		graph.link(graph.root, node.ID, "loaded", "kernel", "high", module.FileState)
	}
	for _, module := range snapshot.Kernel.Dormant {
		story := a.read(module.Facts, false)
		key := module.Name
		if module.File != "" {
			key = module.File
		}
		node := graph.Node("module", key, module.Name, module.File, story.origin, KernelAsset,
			"dormant · "+story.why)
		graph.link(graph.root, node.ID, "dormant", "module-tree", "high", "not loaded")
	}
	for _, hidden := range snapshot.Kernel.Hidden {
		node := graph.Node("module", hidden.Name, hidden.Name, hiddenPath(hidden), Unknown, KernelAsset,
			"hidden from /proc/modules; seen in "+strings.Join(hidden.Views, ", "))
		node.Missing = true
		graph.link(graph.root, node.ID, "hidden", "kernel", "high", "")
	}
	for _, pid := range snapshot.Kernel.HiddenPIDs {
		node := graph.Node("process", strconv.Itoa(pid), strconv.Itoa(pid), fmt.Sprintf("/proc/%d", pid),
			Unknown, KernelAsset, "alive but absent from /proc")
		node.Missing = true
		graph.link(graph.root, node.ID, "hidden", "kernel", "high", "")
	}
	return graph.GraphView("domain", snapshot)
}

// authorityGraph is the setuid/setgid/capability surface with its bits.
func authorityGraph(snapshot *Snapshot) *GraphView {
	graph := domainRoot("domain", "authority", "setuid, setgid and capability objects", RootAsset)
	a := newAssessor(snapshot)
	for _, path := range snapshot.Authority {
		facts := snapshot.Facts(path)
		story := a.read(facts, true)
		bit := authorityBit(facts)
		node := graph.Node("authority", path, path, path, story.origin, authorityReach(facts),
			fmt.Sprintf("mode %s · %s", facts.Mode.Perm(), bit))
		kind := "contains"
		if bit != "no authority bit" {
			kind = "grants"
		}
		graph.link(graph.root, node.ID, kind, "stat", "high", bit)
	}
	return graph.GraphView("domain", snapshot)
}

// bootGraph is the activation tree: the surfaces, the triggers that hang from
// them, and the targets the triggers act on, with each end's origin on the
// node. It is the persistence module's graph; the findings it overlays come
// from the same edges' judge.
func bootGraph(snapshot *Snapshot) *GraphView {
	graph := domainRoot("domain", "boot", "the activation surfaces the host acts on", RootAsset)
	a := newAssessor(snapshot)
	surfaces := map[string]*GraphNode{}
	for _, edge := range snapshot.Activations {
		if edge.Context {
			continue
		}
		surface, ok := surfaces[string(edge.Surface)]
		if !ok {
			surface = graph.Node("surface", string(edge.Surface), string(edge.Surface), "",
				Unknown, RootAsset, "")
			// A surface is the graph's structure, so it is context: no origin
			// to read and no unknown marker to carry.
			surface.Context = true
			surface.Origin = ""
			surfaces[string(edge.Surface)] = surface
			graph.link(graph.root, surface.ID, "acts-at", "boot", "high", "")
		}
		triggerStory := a.read(edge.TriggerFacts, false)
		trigger := graph.Node("trigger", edge.Trigger, edge.Trigger, edge.Trigger,
			triggerStory.origin, edgeReach(edge),
			edge.Phase.String()+" · runs as "+valueOr(edge.Subject.String(), "-"))
		graph.link(surface.ID, trigger.ID, "triggers", "startup", "high", "")
		if edge.Dynamic {
			id := edge.Trigger + " (dynamic)"
			target := graph.Node("target", id, "(dynamic)", "", triggerStory.origin, edgeReach(edge),
				string(edge.Mechanism)+" · the static read cannot name it")
			graph.link(trigger.ID, target.ID, "runs", "startup", "low", string(edge.Mechanism))
			continue
		}
		if edge.Target == "" || edge.Target == edge.Trigger {
			// A self-edge: the trigger node already carries the object, and
			// the mechanism stays on the link to it.
			continue
		}
		targetStory := a.read(edge.TargetFacts, false)
		target := graph.Node("target", edge.Target, edge.Target, edge.Target,
			targetStory.origin, edgeReach(edge), string(edge.Mechanism))
		graph.link(trigger.ID, target.ID, "runs", "startup", "high", string(edge.Mechanism))
	}
	return graph.GraphView("domain", snapshot)
}

// AttachFindings attaches the findings the domain stamped and the coverage
// the run answered. The graph is the picture; the findings are its broken
// edges.
func (p *GraphView) AttachFindings(domain Domain, findings []Finding, coverage []string) {
	p.Findings = domainFindings(domain, findings)
	p.Coverage = coverage
}

// domainFindings keeps the findings the domain stamped.
func domainFindings(bit Domain, findings []Finding) []Finding {
	var out []Finding
	for _, finding := range findings {
		if finding.Domain&bit != 0 {
			out = append(out, finding)
		}
	}
	return out
}
