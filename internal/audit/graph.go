package audit

// Graph is the one relation store behind every picture karma draws: a
// profile's object closure, a domain graph, and the nodes a finding's trace
// points at. Node identity is `kind:key`, where key is the object's own
// name — a path, a pid, an account — and the display text is a field, so a
// formatting change cannot silently change what a graph join means.

import "sort"

// nodeKey builds a node's identity.
func nodeKey(kind, key string) string { return kind + ":" + key }

// Graph accumulates nodes in insertion order and edges deduplicated by their
// full relation.
type Graph struct {
	root     string
	nodes    map[string]*ProfileNode
	order    []string
	edges    []ProfileEdge
	edgeSeen map[string]bool
}

// NewGraph starts a graph with its root node.
func NewGraph(root *ProfileNode) *Graph {
	graph := &Graph{nodes: map[string]*ProfileNode{}, edgeSeen: map[string]bool{}}
	return graph.add(root)
}

// add registers one node and keeps insertion order for the tree. The first
// registration of an identity wins; callers that want a detail updated should
// build the node once and link to it.
func (g *Graph) add(node *ProfileNode) *Graph {
	if _, ok := g.nodes[node.ID]; ok {
		return g
	}
	g.nodes[node.ID] = node
	g.order = append(g.order, node.ID)
	if g.root == "" {
		g.root = node.ID
	}
	return g
}

func (g *Graph) node(id string) *ProfileNode {
	return g.nodes[id]
}

// Node builds and registers one node from its parts.
func (g *Graph) Node(kind, key, name, path string, origin Origin, reach Reach, detail string) *ProfileNode {
	candidate := &ProfileNode{
		ID: nodeKey(kind, key), Kind: kind, Name: name, Path: path,
		Origin: origin.String(), Reach: reach.String(),
		Detail: detail, origin: origin, reach: reach,
	}
	g.add(candidate)
	return g.nodes[candidate.ID]
}

// link records one relation. Source states who produced it (kernel, unit,
// package, tree, shell, elf, jar, cmdline, lexical) and confidence how much
// the read trusts it.
func (g *Graph) link(from, to, kind, source, confidence, note string) {
	if from == "" || to == "" || from == to {
		return
	}
	key := from + "\x00" + to + "\x00" + kind + "\x00" + source
	if g.edgeSeen[key] {
		return
	}
	g.edgeSeen[key] = true
	g.edges = append(g.edges, ProfileEdge{
		From: from, To: to, Kind: kind, Source: source, Confidence: confidence, Note: note,
	})
}

// Profile converts the accumulated graph into the rendered value, with the
// edges sorted for a stable output.
func (g *Graph) Profile(rootKind string, snapshot *Snapshot) *Profile {
	profile := &Profile{
		Root:     g.root,
		RootKind: rootKind,
	}
	if snapshot != nil {
		profile.Boundary = snapshot.Boundary
	}
	for _, id := range g.order {
		profile.Nodes = append(profile.Nodes, *g.nodes[id])
	}
	profile.Edges = append([]ProfileEdge(nil), g.edges...)
	sort.Slice(profile.Edges, func(i, j int) bool {
		left, right := profile.Edges[i], profile.Edges[j]
		if left.From != right.From {
			return left.From < right.From
		}
		if left.To != right.To {
			return left.To < right.To
		}
		return left.Kind < right.Kind
	})
	return profile
}

// steps builds a trace from display texts.
func steps(texts ...string) []Step {
	out := make([]Step, 0, len(texts))
	for _, text := range texts {
		out = append(out, Step{Text: text})
	}
	return out
}

// each walks the nodes in insertion order.
func (g *Graph) each(visit func(*ProfileNode)) {
	for _, id := range g.order {
		visit(g.nodes[id])
	}
}
