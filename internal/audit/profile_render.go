package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// RenderGraph prints one relation graph — a domain or one object — findings
// first, then the tree the evidence built. The tree keeps the edge's source
// in the label, so a kernel observation, a unit declaration and a lexical
// lead are not read as the same kind of fact.
func RenderGraph(w io.Writer, profile *Profile, options RenderOptions) {
	renderObject(w, profile, options, "GRAPH", "no finding touches this graph; the edges below are its evidence")
}

func renderObject(w io.Writer, profile *Profile, options RenderOptions, label, quiet string) {
	width := reportWidth(options.Width)
	node := profileNode(profile, profile.Root)
	root := profile.Root
	if node != nil {
		root = node.Name
		if node.Kind == "file" {
			root = node.Path
		}
	}
	fmt.Fprintln(w, band(" "+label, valueOr(root, profile.Root), width, bannerBG, bannerFG, true, options.Color))
	facts := []fact{
		{label: "root", value: valueOr(profile.RootKind+" "+root, "unknown")},
		{label: "boundary", value: boundaryText(profile.Boundary), full: true},
		{label: "graph", value: fmt.Sprintf("%d nodes · %d edges · %d findings",
			len(profile.Nodes), len(profile.Edges), len(profile.Findings)), full: true},
	}
	head := band(" "+options.Version, clock(), width-2, subBandBG, subBandFG, false, options.Color)
	fmt.Fprintln(w, rail(head, factGrid(facts, width-2), width, mutedColor, options.Color))
	fmt.Fprintln(w)

	if len(profile.Findings) == 0 {
		fmt.Fprintln(w, rail(band(" QUIET", "", width-2, subBandBG, subBandFG, false, options.Color),
			[]string{quiet}, width, mutedColor, options.Color))
		fmt.Fprintln(w)
	}
	for _, finding := range profile.Findings {
		fmt.Fprintln(w, findingPanel(finding, options, width))
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, band(" GRAPH", profile.Root, width, bannerBG, bannerFG, true, options.Color))
	for _, line := range profileTree(profile, options, width) {
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w)
	if len(profile.Coverage) > 0 {
		fmt.Fprintln(w, evidencePanel("COVERAGE", profile.Coverage, len(profile.Coverage), options, width))
	}
}

func profileNode(profile *Profile, id string) *ProfileNode {
	for index := range profile.Nodes {
		if profile.Nodes[index].ID == id {
			return &profile.Nodes[index]
		}
	}
	return nil
}

func profileTree(profile *Profile, options RenderOptions, width int) []string {
	byID := map[string]*ProfileNode{}
	for index := range profile.Nodes {
		byID[profile.Nodes[index].ID] = &profile.Nodes[index]
	}
	outgoing := map[string][]ProfileEdge{}
	for _, edge := range profile.Edges {
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
				profileLine(child, options.Color, room))
			if visited[child.ID] {
				lines = append(lines, childPrefix+paintText(options.Color, fg(mutedColor), "(shown above)"))
				continue
			}
			visited[child.ID] = true
			renderChildren(child.ID, childPrefix, depth+1)
		}
	}
	root := byID[profile.Root]
	if root != nil {
		lines = append(lines, profileLine(root, options.Color, width))
		visited[root.ID] = true
		renderChildren(root.ID, "", 0)
	}
	// A node the walk added without a connecting edge still prints, so a
	// discovery cannot be lost to a missing relation.
	for index := range profile.Nodes {
		node := &profile.Nodes[index]
		if visited[node.ID] {
			continue
		}
		visited[node.ID] = true
		lines = append(lines, paintText(options.Color, fg(mutedColor), "· ")+
			profileLine(node, options.Color, width-2))
		renderChildren(node.ID, "  ", 0)
	}
	return lines
}

func profileLine(node *ProfileNode, color bool, width int) string {
	marker, colorCode := profileMarker(node)
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
		line += paintText(color, fg(mutedColor), "  "+origin)
	}
	if detail != "" {
		line += paintText(color, fg(mutedColor), "  "+detail)
	}
	return line
}

func profileMarker(node *ProfileNode) (string, int) {
	switch {
	case node.Missing:
		return "?", 214
	case node.Context, node.Kind == "socket":
		return "·", mutedColor
	case node.origin == Runtime:
		return "!", 203
	case node.origin == Modified:
		return "!", 214
	case node.origin == Unknown && node.Kind != "package" && node.Kind != "unit":
		return "?", mutedColor
	}
	return "·", mutedColor
}

// WriteGraphJSON writes the graph as data: nodes, edges, findings and the
// coverage that says how far the walk reached.
func WriteGraphJSON(w io.Writer, profile *Profile) error {
	type boundaryJSON struct {
		Time       string `json:"time,omitempty"`
		Kind       string `json:"kind"`
		Source     string `json:"source"`
		Confidence string `json:"confidence"`
	}
	type findingJSON struct {
		Class    string   `json:"class"`
		Severity string   `json:"severity"`
		Title    string   `json:"title"`
		Path     string   `json:"path"`
		Origin   string   `json:"origin"`
		Reach    string   `json:"reach"`
		Detail   string   `json:"detail,omitempty"`
		Chain    []string `json:"chain,omitempty"`
		Nodes    []string `json:"nodes,omitempty"`
		Evidence []string `json:"evidence,omitempty"`
	}
	type profileJSON struct {
		Root     string        `json:"root"`
		RootKind string        `json:"root_kind"`
		Boundary boundaryJSON  `json:"boundary"`
		Nodes    []ProfileNode `json:"nodes"`
		Edges    []ProfileEdge `json:"edges"`
		Findings []findingJSON `json:"findings"`
		Coverage []string      `json:"coverage,omitempty"`
	}
	out := profileJSON{
		Root: profile.Root, RootKind: profile.RootKind,
		Boundary: boundaryJSON{
			Kind: profile.Boundary.Kind, Source: profile.Boundary.Source,
			Confidence: profile.Boundary.Confidence.String(),
		},
		Nodes: profile.Nodes, Edges: profile.Edges,
		Coverage: profile.Coverage,
	}
	if !profile.Boundary.Time.IsZero() {
		out.Boundary.Time = profile.Boundary.Time.Format("2006-01-02T15:04:05Z07:00")
	}
	for _, finding := range profile.Findings {
		out.Findings = append(out.Findings, findingJSON{
			Class: finding.Class, Severity: finding.Severity.String(), Title: finding.Title,
			Path: finding.Path, Origin: finding.Origin.String(), Reach: finding.Reach.String(),
			Detail: finding.Detail, Chain: traceTexts(finding.Trace),
			Nodes: traceNodes(finding.Trace), Evidence: finding.Evidence,
		})
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(out)
}
