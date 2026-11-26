package audit

// GraphBuilder is the one relation store behind every picture karma draws: a
// object graphs' relation closure, a domain graph, and the nodes a finding's trace
// points at. Node identity is `kind:key`, where key is the object's own
// name — a path, a pid, an account — and the display text is a field, so a
// formatting change cannot silently change what a graph join means.

import "sort"

// nodeKey builds a node's identity.
func nodeKey(kind, key string) string { return kind + ":" + key }

// GraphBuilder accumulates nodes in insertion order and edges deduplicated by their
// full relation.
type GraphBuilder struct {
	root     string
	nodes    map[string]*GraphNode
	order    []string
	edges    []GraphEdge
	edgeSeen map[string]bool
}

// NewGraphBuilder starts a graph with its root node.
func NewGraphBuilder(root *GraphNode) *GraphBuilder {
	graph := &GraphBuilder{nodes: map[string]*GraphNode{}, edgeSeen: map[string]bool{}}
	return graph.add(root)
}

// add registers one node and keeps insertion order for the tree. The first
// registration of an identity wins; callers that want a detail updated should
// build the node once and link to it.
func (g *GraphBuilder) add(node *GraphNode) *GraphBuilder {
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

func (g *GraphBuilder) node(id string) *GraphNode {
	return g.nodes[id]
}

// setRoot names the object a graph is about. Insertion order decides nothing
// about the answer: a seed may register the package that owns it before its
// own node, and the root still has to be the object the operator asked for.
func (g *GraphBuilder) setRoot(id string) *GraphBuilder {
	g.root = id
	return g
}

// Node builds and registers one node from its parts.
func (g *GraphBuilder) Node(kind, key, name, path string, origin Origin, reach Reach, detail string) *GraphNode {
	candidate := &GraphNode{
		ID: nodeKey(kind, key), Kind: kind, Name: name, Path: path,
		Origin: origin.String(), Reach: reach.String(),
		Detail: detail,
	}
	g.add(candidate)
	return g.nodes[candidate.ID]
}

// link records one relation. Source states who produced it (kernel, unit,
// package, tree, shell, elf, jar, cmdline, lexical) and confidence how much
// the read trusts it.
func (g *GraphBuilder) link(from, to, kind, source, confidence, note string) {
	if from == "" || to == "" || from == to {
		return
	}
	key := from + "\x00" + to + "\x00" + kind + "\x00" + source
	if g.edgeSeen[key] {
		return
	}
	g.edgeSeen[key] = true
	g.edges = append(g.edges, GraphEdge{
		From: from, To: to, Kind: kind, Source: source, Confidence: confidence, Note: note,
	})
}

// GraphView converts the accumulated graph into the rendered value, with the
// edges sorted for a stable output.
func (g *GraphBuilder) GraphView(rootKind string, snapshot *Snapshot) *GraphView {
	view := &GraphView{
		Root:     g.root,
		RootKind: rootKind,
	}
	if snapshot != nil {
		view.Boundary = snapshot.Boundary
	}
	for _, id := range g.order {
		view.Nodes = append(view.Nodes, *g.nodes[id])
	}
	view.Edges = append([]GraphEdge(nil), g.edges...)
	sort.Slice(view.Edges, func(i, j int) bool {
		left, right := view.Edges[i], view.Edges[j]
		if left.From != right.From {
			return left.From < right.From
		}
		if left.To != right.To {
			return left.To < right.To
		}
		return left.Kind < right.Kind
	})
	return view
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
func (g *GraphBuilder) each(visit func(*GraphNode)) {
	for _, id := range g.order {
		visit(g.nodes[id])
	}
}
