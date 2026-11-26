package audit

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// RenderGraph prints one relation graph — a domain or one object — in the
// page language every command wears: the karma masthead, the findings, then
// the tree the evidence built. The tree keeps the edge's source in the
// label, so a kernel observation, a unit declaration and a lexical lead are
// not read as the same kind of fact.
func RenderGraph(w io.Writer, view *GraphView, options RenderOptions) {
	width := reportWidth(options.Width)
	fmt.Fprintln(w, band(" KARMA", "yuyy ", width, bannerBG, bannerFG, true, options.Color))
	head := band(" "+versionText(options), clock(), width-2, subBandBG, subBandFG, false, options.Color)
	root := graphRootName(view)
	facts := []fact{
		{label: "root", value: valueOr(view.RootKind+" "+root, "unknown")},
		{label: "boundary", value: boundaryText(view.Boundary), full: true},
		{label: "graph", value: fmt.Sprintf("%d nodes · %d edges · %d findings",
			len(view.Nodes), len(view.Edges), len(view.Findings)), full: true},
	}
	fmt.Fprintln(w, rail(head, factGrid(facts, width-2), width, mutedColor, options.Color))
	fmt.Fprintln(w)
	if len(view.Findings) == 0 {
		fmt.Fprintln(w, rail(band(" QUIET", "", width-2, subBandBG, subBandFG, false, options.Color),
			[]string{"no finding touches this graph; the edges below are its evidence"},
			width, mutedColor, options.Color))
		fmt.Fprintln(w)
	}
	for _, finding := range view.Findings {
		fmt.Fprintln(w, findingPanel(finding, options, width))
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, band(" GRAPH", root, width, bannerBG, bannerFG, true, options.Color))
	for _, line := range graphTree(view, options, width) {
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w)
	if len(view.Coverage) > 0 {
		fmt.Fprintln(w, evidencePanel("COVERAGE", view.Coverage, len(view.Coverage), options, width))
	}
}

// graphRootName names the graph's root the way a person names it: the path
// of a file, the name of anything else, the node id when the root never
// rendered.
func graphRootName(view *GraphView) string {
	if node := viewNode(view, view.Root); node != nil {
		if node.Kind == "file" {
			return node.Path
		}
		return node.Name
	}
	return view.Root
}

func viewNode(view *GraphView, id string) *GraphNode {
	for index := range view.Nodes {
		if view.Nodes[index].ID == id {
			return &view.Nodes[index]
		}
	}
	return nil
}

func graphTree(view *GraphView, options RenderOptions, width int) []string {
	byID := map[string]*GraphNode{}
	for index := range view.Nodes {
		byID[view.Nodes[index].ID] = &view.Nodes[index]
	}
	outgoing := map[string][]GraphEdge{}
	for _, edge := range view.Edges {
		outgoing[edge.From] = append(outgoing[edge.From], edge)
	}
	for from := range outgoing {
		sort.Slice(outgoing[from], func(i, j int) bool {
			left, right := outgoing[from][i], outgoing[from][j]
			if left.Kind != right.Kind {
				return left.Kind < right.Kind
			}
			return left.To < right.To
		})
	}
	var lines []string
	visited := map[string]bool{}
	var renderChildren func(id, prefix string, depth int)
	renderChildren = func(id, prefix string, depth int) {
		if depth > 8 {
			lines = append(lines, prefix+paintText(options.Color, fg(mutedColor), "… deeper edges omitted"))
			return
		}
		edges := outgoing[id]
		for index, edge := range edges {
			child := byID[edge.To]
			if child == nil {
				continue
			}
			last := index == len(edges)-1
			branch, childPrefix := "├─ ", prefix+"│  "
			if last {
				branch, childPrefix = "└─ ", prefix+"   "
			}
			edgeText := edge.Kind + "[" + edge.Source + "] "
			room := width - displayWidth(prefix) - displayWidth(branch) - displayWidth(edgeText)
			lines = append(lines, prefix+branch+
				paintText(options.Color, fg(mutedColor), edgeText)+
				nodeLine(child, options.Color, room))
			if visited[child.ID] {
				lines = append(lines, childPrefix+paintText(options.Color, fg(mutedColor), "(shown above)"))
				continue
			}
			visited[child.ID] = true
			renderChildren(child.ID, childPrefix, depth+1)
		}
	}
	root := byID[view.Root]
	if root != nil {
		lines = append(lines, nodeLine(root, options.Color, width))
		visited[root.ID] = true
		renderChildren(root.ID, "", 0)
	}
	// A node the walk added without a connecting edge still prints, so a
	// discovery cannot be lost to a missing relation.
	for index := range view.Nodes {
		node := &view.Nodes[index]
		if visited[node.ID] {
			continue
		}
		visited[node.ID] = true
		lines = append(lines, paintText(options.Color, fg(mutedColor), "· ")+
			nodeLine(node, options.Color, width-2))
		renderChildren(node.ID, "  ", 0)
	}
	return lines
}

// nodeLine is one tree line: the marker, the label, the origin in the hue
// the origin language gives it, and the detail that fits the line.
func nodeLine(node *GraphNode, color bool, width int) string {
	marker, colorCode := nodeMarker(node)
	label := node.Kind + " " + node.Name
	if node.Kind == "file" || node.Kind == "dir" {
		label = node.Kind + " " + node.Path
	}
	detail := node.Detail
	if node.Content != nil {
		switch node.Content.State {
		case Verified:
			detail = strings.TrimSpace("md5 verified · " + detail)
		case Mismatched:
			detail = strings.TrimSpace("md5 mismatch · " + detail)
		}
	}
	origin := node.Origin
	if width > 0 {
		room := width - displayWidth(label) - displayWidth(origin) - 4
		if room > 0 {
			detail = truncate(detail, room)
		} else {
			detail = ""
		}
	}
	line := paintText(color, fg(colorCode), marker) + " " + label
	if origin != "" {
		line += paintText(color, fg(originHue(node.origin)), "  "+origin)
	}
	if detail != "" {
		line += paintText(color, fg(mutedColor), "  "+detail)
	}
	return line
}

// nodeMarker is the tree's origin language: a missing path asks a question
// in the caution hue, a runtime or modified object is marked warm, an
// unknown artifact a quiet question, and a context node a quiet dot.
func nodeMarker(node *GraphNode) (string, int) {
	switch {
	case node.Missing:
		return "?", hueCaution
	case node.Context, node.Kind == "socket":
		return "·", mutedColor
	case node.origin == Runtime:
		return "!", hueAlert
	case node.origin == Modified:
		return "!", hueCaution
	case node.origin == Unknown && node.Kind != "package" && node.Kind != "unit":
		return "?", mutedColor
	}
	return "·", mutedColor
}

// WriteGraphJSON writes the graph as data: nodes, edges, findings and the
// coverage that says how far the walk reached.
func WriteGraphJSON(w io.Writer, view *GraphView) error {
	findings := make([]findingData, 0, len(view.Findings))
	for _, finding := range view.Findings {
		findings = append(findings, findingDataOf(finding))
	}
	return encode(w, struct {
		Root     string        `json:"root"`
		RootKind string        `json:"root_kind"`
		Boundary boundaryData  `json:"boundary"`
		Nodes    []GraphNode   `json:"nodes"`
		Edges    []GraphEdge   `json:"edges"`
		Findings []findingData `json:"findings"`
		Coverage []string      `json:"coverage,omitempty"`
	}{
		Root: view.Root, RootKind: view.RootKind,
		Boundary: boundaryDataOf(view.Boundary),
		Nodes:    view.Nodes, Edges: view.Edges,
		Findings: findings,
		Coverage: view.Coverage,
	})
}
