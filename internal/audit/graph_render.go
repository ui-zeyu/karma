package audit

import (
	"fmt"
	"io"
	"sort"
	"strings"

	chrome "karma/internal/panel"
)

// RenderGraph prints one relation graph — a domain or one object — in the
// page language every command wears: the karma masthead, the findings, then
// the tree the evidence built. The tree keeps the edge's source in the
// label, so a kernel observation, a unit declaration and a lexical lead are
// not read as the same kind of fact.
func RenderGraph(w io.Writer, view *GraphView, options RenderOptions) {
	width := reportWidth(options.Width)
	root := graphRootName(view)
	options.Root = graphRootPath(view)
	writeMasthead(w, options, width, []fact{
		{label: "root", value: valueOr(view.RootKind+" "+root, "unknown")},
		{label: "boundary", value: boundaryText(view.Boundary), full: true},
		{label: "graph", value: fmt.Sprintf("%d nodes · %d edges · %d findings",
			len(view.Nodes), len(view.Edges), len(view.Findings)), full: true},
	}, nil)
	if len(view.Findings) == 0 {
		fmt.Fprintln(w, quietPanel("no finding touches this graph; the edges below are its evidence", options, width))
		fmt.Fprintln(w)
	}
	for _, group := range groupFindings(view.Findings) {
		fmt.Fprintln(w, findingPanel(panelGroup{findings: group}, true, options, width))
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, chrome.Band(" GRAPH", chrome.SafeText(root), width, bannerBG, bannerFG, true, options.Color))
	for _, line := range graphTree(view, options, width) {
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w)
	if len(view.Coverage) > 0 {
		fmt.Fprintln(w, coveragePanel(view.Coverage, options, width))
	}
}

// graphRootName names the graph's root the way a person names it: the path
// of a file, the name of anything else, the node id when the root never
// rendered.
func graphRootName(view *GraphView) string {
	if node := viewNode(view, view.Root); node != nil {
		if node.Kind == "file" || node.Kind == "dir" {
			return node.Path
		}
		return node.Name
	}
	return view.Root
}

// graphRootPath is the filesystem object the page is rooted at, when it has
// one. A finding on that same object does not need a second graph command.
func graphRootPath(view *GraphView) string {
	if node := viewNode(view, view.Root); node != nil {
		return node.Path
	}
	return ""
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
			lines = append(lines, prefix+chrome.Paint(options.Color, chrome.Fg(mutedColor), "… deeper edges omitted"))
			return
		}
		edges := outgoing[id]
		links := make([]GraphEdge, 0, len(edges))
		for _, edge := range edges {
			if byID[edge.To] != nil {
				links = append(links, edge)
			}
		}
		for index, edge := range links {
			child := byID[edge.To]
			last := index == len(links)-1
			branch, childPrefix := "├─ ", prefix+"│  "
			if last {
				branch, childPrefix = "└─ ", prefix+"   "
			}
			edgeText := edge.Kind + "[" + edge.Source + "] "
			room := width - chrome.DisplayWidth(prefix) - chrome.DisplayWidth(branch) - chrome.DisplayWidth(edgeText)
			lines = append(lines, prefix+branch+
				chrome.Paint(options.Color, chrome.Fg(mutedColor), edgeText)+
				nodeLine(child, options.Color, room))
			if visited[child.ID] {
				lines = append(lines, childPrefix+chrome.Paint(options.Color, chrome.Fg(mutedColor), "(shown above)"))
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
		lines = append(lines, chrome.Paint(options.Color, chrome.Fg(mutedColor), "· ")+
			nodeLine(node, options.Color, width-2))
		renderChildren(node.ID, "  ", 0)
	}
	return lines
}

// nodeLine is one tree line: the marker, the label, the origin in the hue
// the origin language gives it, and the detail that fits the line.
func nodeLine(node *GraphNode, color bool, width int) string {
	marker, colorCode := nodeMarker(node)
	label := node.Kind + " " + chrome.SafeText(node.Name)
	if node.Kind == "file" || node.Kind == "dir" {
		label = node.Kind + " " + chrome.SafeText(node.Path)
	}
	detail := chrome.SafeText(node.Detail)
	if node.Content != nil {
		switch node.Content.State {
		case Verified:
			detail = strings.TrimSpace("content verified · " + detail)
		case Mismatched:
			detail = strings.TrimSpace("content mismatch · " + detail)
		}
	}
	// A context node is structure, not evidence: it states no origin word,
	// whatever the builder stored.
	origin := ""
	if !node.Context {
		origin = chrome.SafeText(node.Origin)
	}
	if width > 0 {
		// marker + space + label, then "  origin" when present, then
		// "  detail": the optional origin shifts the detail's room by two.
		used := 2 + chrome.DisplayWidth(label)
		if origin != "" {
			used += 2 + chrome.DisplayWidth(origin)
		}
		room := width - used - 2
		if room > 0 {
			detail = chrome.Truncate(detail, room)
		} else {
			detail = ""
		}
	}
	line := chrome.Paint(color, chrome.Fg(colorCode), marker) + " " + label
	if origin != "" {
		line += chrome.Paint(color, chrome.Fg(originHue(node.typedOrigin())), "  "+origin)
	}
	if detail != "" {
		line += chrome.Paint(color, chrome.Fg(mutedColor), "  "+detail)
	}
	return line
}

// nodeMarker is the tree's origin language: a missing path asks a question
// in the caution hue, a runtime or modified object is marked warm, an
// unknown artifact a quiet question, and a context node a quiet dot.
func nodeMarker(node *GraphNode) (string, int) {
	origin := node.typedOrigin()
	switch {
	case node.Missing:
		return "?", hueCaution
	case node.Context, node.Kind == "socket":
		return "·", mutedColor
	case origin == Runtime:
		return "!", hueAlert
	case origin == Modified:
		return "!", hueCaution
	case origin == Unknown && node.Kind != "package" && node.Kind != "unit":
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
		Coverage []Coverage    `json:"coverage,omitempty"`
	}{
		Root: view.Root, RootKind: view.RootKind,
		Boundary: boundaryDataOf(view.Boundary),
		Nodes:    view.Nodes, Edges: view.Edges,
		Findings: findings,
		Coverage: view.Coverage,
	})
}
