package audit

import (
	"fmt"
	"strings"
	"testing"

	chrome "karma/internal/panel"
	"karma/internal/startup"
	"karma/internal/trust"
)

func TestGroupKeysStayAdjacentAfterSortFindings(t *testing.T) {
	member := func(title string) Finding {
		return Finding{
			Class: "identity-factor", Severity: High, Title: title,
			Path: "/etc/passwd", Origin: Unknown, Reach: RootAsset,
		}
	}
	findings := []Finding{member("X"), member("Y"), member("X")}
	sortFindings(findings)
	groups := groupFindings(findings)
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want two titles in adjacent runs", len(groups))
	}
	if len(groups[0]) != 2 || groups[0][0].Title != "X" {
		t.Errorf("first group = %+v, want the two X relations", groups[0])
	}
	if len(groups[1]) != 1 || groups[1][0].Title != "Y" {
		t.Errorf("second group = %+v, want the Y relation", groups[1])
	}
}

func TestDirectoryRollupSummarizesManyFiles(t *testing.T) {
	dir := "/usr/local/lib"
	var findings []Finding
	for index := 0; index < directoryRollupThreshold; index++ {
		findings = append(findings, Finding{
			Class: "unowned-file", Severity: High, Title: "root-level executable no package owns",
			Path: fmt.Sprintf("%s/tool%d", dir, index), Origin: Runtime, Reach: RootAsset,
			Detail: "an executable at the filesystem root is an entrypoint or a dropped payload",
		})
	}
	plain := chrome.StripANSI(renderText(t, layoutReport(findings), RenderOptions{Width: 100}))
	for _, want := range []string{
		"HIGH  " + dir,
		fmt.Sprintf("%d files in this directory carry the same judgment", directoryRollupThreshold),
		"· next  karma audit " + dir,
	} {
		if !strings.Contains(plain, want) {
			t.Errorf("rollup misses %q:\n%s", want, plain)
		}
	}
	for index := 0; index < directoryRollupThreshold; index++ {
		if !strings.Contains(plain, fmt.Sprintf("tool%d", index)) {
			t.Errorf("rollup misses tool%d:\n%s", index, plain)
		}
	}
	if strings.Contains(plain, "HIGH  "+dir+"/tool") {
		t.Errorf("rollup still prints every per-file head:\n%s", plain)
	}
}

func TestDirectoryRollupLeavesAScopedDirectoryOpen(t *testing.T) {
	dir := "/usr/local/lib"
	var findings []Finding
	for index := 0; index < directoryRollupThreshold; index++ {
		findings = append(findings, Finding{
			Class: "unowned-file", Severity: High, Title: "root-level executable no package owns",
			Path: fmt.Sprintf("%s/tool%d", dir, index), Origin: Runtime, Reach: RootAsset,
		})
	}
	plain := chrome.StripANSI(renderText(t, layoutReport(findings),
		RenderOptions{Width: 100, Filter: Filter{Paths: []string{dir}}}))
	for index := 0; index < directoryRollupThreshold; index++ {
		if !strings.Contains(plain, "HIGH  "+fmt.Sprintf("%s/tool%d", dir, index)) {
			t.Errorf("a directory scope hides tool%d:\n%s", index, plain)
		}
	}
	if strings.Contains(plain, "files in this directory carry the same judgment") {
		t.Errorf("a directory scope still rolls the files up:\n%s", plain)
	}
}

func TestDirectoryRollupKeepsDistinctJudgmentDetails(t *testing.T) {
	dir := "/etc"
	var findings []Finding
	for index := 0; index < directoryRollupThreshold; index++ {
		findings = append(findings, Finding{
			Class: "activation-introduction", Severity: Critical,
			Title: "runtime object in an activation surface",
			Path:  fmt.Sprintf("%s/file%d", dir, index), Origin: Runtime, Reach: RootAsset,
			Detail: fmt.Sprintf("exec in %s/file%d activates /opt/payload%d", dir, index, index),
		})
	}
	plain := chrome.StripANSI(renderText(t, layoutReport(findings), RenderOptions{Width: 100}))
	if strings.Contains(plain, "files in this directory carry the same judgment") {
		t.Errorf("distinct judgments were rolled into one directory panel:\n%s", plain)
	}
	for index := 0; index < directoryRollupThreshold; index++ {
		if !strings.Contains(plain, "CRITICAL  "+fmt.Sprintf("%s/file%d", dir, index)) {
			t.Errorf("distinct file%d was hidden:\n%s", index, plain)
		}
	}
}

func TestDirectoryRollupNeedsEnoughFiles(t *testing.T) {
	dir := "/usr/local/lib"
	var findings []Finding
	for index := 0; index < directoryRollupThreshold-1; index++ {
		findings = append(findings, Finding{
			Class: "unowned-file", Severity: High, Title: "executable in a program directory no package owns",
			Path: fmt.Sprintf("%s/tool%d", dir, index), Origin: Runtime, Reach: RootAsset,
		})
	}
	plain := chrome.StripANSI(renderText(t, layoutReport(findings), RenderOptions{Width: 100}))
	if strings.Contains(plain, "files in this directory carry the same judgment") {
		t.Errorf("a short list rolls up:\n%s", plain)
	}
	for index := 0; index < directoryRollupThreshold-1; index++ {
		if !strings.Contains(plain, "HIGH  "+fmt.Sprintf("%s/tool%d", dir, index)) {
			t.Errorf("short list misses tool%d:\n%s", index, plain)
		}
	}
}

func TestEmptyShowSectionCountsZero(t *testing.T) {
	section := &Section{
		Words: []string{"x"}, Panel: "ACTIVATION",
		Rows:  func(view *View, options RenderOptions) []string { return nil },
		Count: func(view *View, options RenderOptions) int { return 0 },
	}
	var out strings.Builder
	RenderShow(&out, &View{Snapshot: &Snapshot{}}, section, "x", RenderOptions{Width: 100})
	plain := chrome.StripANSI(out.String())
	head := ""
	for _, line := range strings.Split(plain, "\n") {
		if strings.Contains(line, "ACTIVATION") {
			head = strings.TrimRight(line, " ")
			break
		}
	}
	if head == "" || !strings.HasSuffix(head, " 0") {
		t.Errorf("empty section head = %q, want count 0:\n%s", head, plain)
	}
	if !strings.Contains(plain, "nothing in this section answers the selected scope") {
		t.Errorf("empty section lacks its explanation:\n%s", plain)
	}
}

func TestMastheadChipsWrapWithoutSplittingABadge(t *testing.T) {
	findings := []Finding{
		layoutFinding(Critical, "a", "/etc/a"), layoutFinding(Low, "b", "/etc/b"),
		layoutFinding(Critical, "c", "/etc/c"), layoutFinding(High, "d", "/etc/d"),
		layoutFinding(Medium, "e", "/etc/e"), layoutFinding(Medium, "f", "/etc/f"),
		layoutFinding(Low, "g", "/etc/g"), layoutFinding(Info, "h", "/etc/h"),
		layoutFinding(Info, "i", "/etc/i"),
	}
	text := chrome.StripANSI(renderText(t, layoutReport(findings), RenderOptions{Width: 70}))
	counts := map[string]string{
		"critical": "2 critical", "high": "1 high", "medium": "2 medium", "low": "2 low", "info": "2 info",
	}
	for _, line := range strings.Split(text, "\n") {
		if width := chrome.DisplayWidth(line); width > 70 {
			t.Errorf("line is %d columns wide: %q", width, line)
		}
		for word, badge := range counts {
			if strings.Contains(line, word) && !strings.Contains(line, badge) {
				t.Errorf("badge %q split across a line break: %q", badge, line)
			}
		}
	}
}

func TestFactGridFitsLongValues(t *testing.T) {
	facts := []fact{
		{label: "host", value: strings.Repeat("h", 80)},
		{label: "distro", value: strings.Repeat("d", 80)},
		{label: "source", value: strings.Repeat("s", 80)},
	}
	for _, line := range factGrid(facts, 60) {
		if width := chrome.DisplayWidth(line); width > 60 {
			t.Errorf("fact row is %d columns wide: %q", width, line)
		}
	}
}

func TestNodeLineFitsTheRequestedWidth(t *testing.T) {
	node := &GraphNode{
		Kind: "file", Name: "x", Path: "/etc/x", Origin: "runtime",
		Detail: strings.Repeat("d", 100),
	}
	if line := nodeLine(node, false, 40); chrome.DisplayWidth(line) > 40 {
		t.Errorf("node line is %d columns wide: %q", chrome.DisplayWidth(line), line)
	}
	node.Origin = ""
	if line := nodeLine(node, false, 40); chrome.DisplayWidth(line) > 40 {
		t.Errorf("originless node line is %d columns wide: %q", chrome.DisplayWidth(line), line)
	}
}

func TestHighlightTokensPaintsPathsInsideAssignments(t *testing.T) {
	line := "export LD_PRELOAD=/lib/__selinux.so"
	painted := highlightTokens(line, 0, true)
	if !strings.Contains(painted, chrome.Fg(hueInformation)+"/lib/__selinux.so") {
		t.Errorf("assignment path is not painted: %q", painted)
	}
	quoted := highlightTokens(`config "/etc/app.conf"`, 0, true)
	if !strings.Contains(quoted, chrome.Fg(hueInformation)+"/etc/app.conf") {
		t.Errorf("quoted path is not painted: %q", quoted)
	}
	url := highlightTokens("see https://example.test/api", 0, true)
	if strings.Contains(url, chrome.Fg(hueInformation)) {
		t.Errorf("a URL path took the file hue: %q", url)
	}
}

func TestNextLineSkipsTheGraphRoot(t *testing.T) {
	path := "/etc/ld.so.preload"
	finding := layoutFinding(Critical, "runtime object", path)
	same := &GraphView{
		Root: "file:" + path, RootKind: "file",
		Nodes:    []GraphNode{{ID: "file:" + path, Kind: "file", Path: path}},
		Findings: []Finding{finding},
	}
	var sameOut strings.Builder
	RenderGraph(&sameOut, same, RenderOptions{Width: 100})
	if strings.Contains(sameOut.String(), "· next") {
		t.Errorf("a graph root repeats its own graph:\n%s", sameOut.String())
	}
	other := &GraphView{
		Root: "file:/etc/other", RootKind: "file",
		Nodes:    []GraphNode{{ID: "file:/etc/other", Kind: "file", Path: "/etc/other"}},
		Findings: []Finding{finding},
	}
	var otherOut strings.Builder
	RenderGraph(&otherOut, other, RenderOptions{Width: 100})
	if !strings.Contains(otherOut.String(), "· next") {
		t.Errorf("a different object loses its graph command:\n%s", otherOut.String())
	}
}

func TestSelfEdgeReadsAsOneObject(t *testing.T) {
	path := "/etc/fstab"
	facts := trust.Build(path, trust.Attrs{
		Kind: trust.File, Mode: 0o644, UID: 0, Real: path, CTime: 1200,
	})
	snapshot := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{path: facts},
		Activations: []startup.Edge{{
			Surface: startup.SurfaceSystem, Phase: startup.BootEnabled,
			Subject: startup.Subject{Class: startup.AccountRoot},
			Trigger: path, Target: path, Mechanism: "fstab", Kind: startup.Config,
			TriggerFacts: facts, TargetFacts: facts,
		}},
	}
	report := Judge(snapshot, Filter{})
	var finding *Finding
	for index := range report.Findings {
		if report.Findings[index].Path == path {
			finding = &report.Findings[index]
			break
		}
	}
	if finding == nil {
		t.Fatalf("self-edge finding missing: %+v", report.Findings)
	}
	if len(finding.Trace) != 1 || finding.Trace[0].Text != path {
		t.Errorf("self-edge trace = %+v, want the file once", finding.Trace)
	}
	if !strings.Contains(finding.Detail, "reads this file by position") {
		t.Errorf("self-edge detail = %q", finding.Detail)
	}
	panel := chrome.StripANSI(findingPanel(panelGroup{findings: findingGroup{*finding}}, false, RenderOptions{}, 100))
	if strings.Contains(panel, "→ fstab") {
		t.Errorf("self-edge still draws a self branch:\n%s", panel)
	}
	if !strings.Contains(panel, "· chain  "+path) {
		t.Errorf("self-edge loses its one-step chain:\n%s", panel)
	}
}

func TestSelfEdgeDoesNotEmitATargetEvidenceLine(t *testing.T) {
	path := "/etc/hosts.allow"
	facts := trust.Build(path, trust.Attrs{Kind: trust.File, Mode: 0o644, UID: 0, Real: path, CTime: 1200})
	snapshot := &Snapshot{
		Boundary: boundary(),
		Objects:  map[string]trust.Facts{path: facts},
		Activations: []startup.Edge{{
			Surface: startup.SurfaceSystem, Phase: startup.BootEnabled,
			Subject: startup.Subject{Class: startup.AccountRoot},
			Trigger: path, Target: path, Mechanism: "hosts.allow", Kind: startup.Config,
			TriggerFacts: facts, TargetFacts: facts,
		}},
	}
	report := Judge(snapshot, Filter{})
	for _, finding := range report.Findings {
		if finding.Path != path {
			continue
		}
		for _, line := range finding.Evidence {
			if strings.HasPrefix(line, "target ") {
				t.Errorf("self-edge evidence repeats the target: %q", line)
			}
		}
		return
	}
	t.Fatalf("self-edge finding missing: %+v", report.Findings)
}

func TestQuoteRowsKeepOneBlockPerPathAcrossTrailCitations(t *testing.T) {
	path := "/etc/cron.d/0systemd-update"
	group := findingGroup{{
		Quotes: []Quote{
			{Path: path, Line: 1, Text: "SHELL=/bin/sh"},
			{Path: "/root/.viminfo", Line: 10, Text: "'3  3  0  " + path},
			{Path: path, Line: 3, Text: "*/10 * * * * root /opt/.lab/beacon.sh"},
		},
	}}
	rows := quoteRows(group, false)
	if count := strings.Count(strings.Join(rows, "\n"), "· cite  "+path); count != 1 {
		t.Errorf("source path printed %d headers, want one:\n%s", count, strings.Join(rows, "\n"))
	}
	plain := strings.Join(rows, "\n")
	if !strings.Contains(plain, "1 │ SHELL=/bin/sh") || !strings.Contains(plain, "3 │ */10 * * * * root") {
		t.Errorf("source lines are not in one block:\n%s", plain)
	}
}

func TestCitationBlocksKeepIdenticalTextFromDifferentFiles(t *testing.T) {
	text := "'3  3  0  /etc/cron.d/0systemd-update"
	finding := Finding{
		Class: "activation-introduction", Severity: Critical, Path: "/etc/cron.d/0systemd-update",
		Quotes: []Quote{
			{Path: "/home/syssupport/.viminfo", Line: 10, Text: text},
			{Path: "/root/.viminfo", Line: 10, Text: text},
		},
	}
	panel := chrome.StripANSI(findingPanel(panelGroup{findings: findingGroup{finding}}, false, RenderOptions{}, 100))
	for _, path := range []string{"/home/syssupport/.viminfo", "/root/.viminfo"} {
		if !strings.Contains(panel, "· cite  "+path) {
			t.Errorf("missing citation header %s:\n%s", path, panel)
		}
	}
	if count := strings.Count(panel, "10 │ "+text); count != 2 {
		t.Errorf("identical text printed %d times, want one row per file:\n%s", count, panel)
	}
}

func TestPaintedTimestampStaysTogether(t *testing.T) {
	line := chrome.Paint(true, chrome.Fg(mutedColor), "trigger ") +
		chrome.Paint(true, chrome.Fg(mutedColor), "2026-11-26") +
		chrome.Paint(true, chrome.Fg(mutedColor), " ") +
		chrome.Paint(true, chrome.Fg(mutedColor), "07:32:06")
	wrapped := chrome.WrapProse(line, 24, 2)
	for _, row := range wrapped {
		plain := chrome.StripANSI(row)
		if strings.Contains(plain, "2026-11-26") && !strings.Contains(plain, "07:32:06") {
			t.Errorf("painted date and clock split: %q\nall: %q", plain, wrapped)
		}
	}
}

func TestTimeStampTokensStayTogether(t *testing.T) {
	// A timestamp is one token to a reader; the prose wrapper must not split
	// the date from the clock when the line is tight.
	line := "trigger /etc/fstab: runtime (created after the boundary (2026-11-26 07:32:06))"
	wrapped := chrome.WrapProse(line, 40, 2)
	for _, row := range wrapped {
		if strings.Contains(row, "2026-11-26") && !strings.Contains(row, "07:32:06") {
			t.Errorf("date and clock split across a line: %q\nall: %q", row, wrapped)
		}
	}
}
