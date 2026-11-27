package audit

// The report's first page: the masthead counts, the severity badge, and the
// hierarchy every finding panel carries.

import (
	"strings"
	"testing"

	chrome "karma/internal/panel"
	"karma/internal/startup"
)

func layoutReport(findings []Finding) *Report {
	sortFindings(findings)
	return &Report{
		Boundary: boundary(),
		Host:     Host{Hostname: "lab", OS: "Ubuntu 24.04", Kernel: "6.8.0", UID: 0},
		Source:   "native",
		Findings: findings,
	}
}

func layoutFinding(severity Severity, title, path string) Finding {
	return layoutClassFinding(severity, "test", title, path)
}

func layoutClassFinding(severity Severity, class Class, title, path string) Finding {
	return Finding{
		Class: class, Severity: severity, Title: title, Path: path,
		Origin: Runtime, Reach: RootAsset,
	}
}

func renderText(t *testing.T, report *Report, options RenderOptions) string {
	t.Helper()
	var out strings.Builder
	Render(&out, report, options)
	return out.String()
}

func TestMastheadCountsTheFindingsBySeverity(t *testing.T) {
	if text := renderText(t, layoutReport(nil), RenderOptions{Width: 100}); !strings.Contains(text, "findings  none") {
		t.Errorf("the quiet masthead misses its counts line:\n%s", text)
	}
	findings := []Finding{
		layoutFinding(Critical, "a", "/etc/a"),
		layoutFinding(Low, "b", "/etc/b"),
		layoutFinding(Critical, "c", "/etc/c"),
		layoutFinding(High, "d", "/etc/d"),
		layoutFinding(Medium, "e", "/etc/e"),
		layoutFinding(Medium, "f", "/etc/f"),
		layoutFinding(Low, "g", "/etc/g"),
		layoutFinding(Info, "h", "/etc/h"),
		layoutFinding(Info, "i", "/etc/i"),
	}
	text := renderText(t, layoutReport(findings), RenderOptions{Width: 100})
	want := "findings  9 ·  2 critical  ·  1 high  ·  2 medium  ·  2 low  ·  2 info"
	if !strings.Contains(text, want) {
		t.Errorf("the masthead misses %q:\n%s", want, text)
	}
	painted := renderText(t, layoutReport(findings), RenderOptions{Width: 100, Color: true})
	for _, chip := range []string{
		chrome.Bg(1) + chrome.Fg(15) + "\x1b[1m 2 critical ",
		chrome.Bg(9) + chrome.Fg(0) + "\x1b[1m 1 high ",
		chrome.Bg(11) + chrome.Fg(0) + "\x1b[1m 2 medium ",
		chrome.Bg(14) + chrome.Fg(15) + "\x1b[1m 2 low ",
		chrome.Bg(mutedColor) + chrome.Fg(0) + "\x1b[1m 2 info ",
	} {
		if !strings.Contains(painted, chip) {
			t.Errorf("the counts line misses the badge %q", chip)
		}
	}
}

func TestFindingHeadWearsTheSeverityBadge(t *testing.T) {
	critical := layoutFinding(Critical, "judgment", "/etc/ld.so.preload")
	plain := findingHead(critical, 98, false)
	if strings.Contains(plain, "\x1b[") {
		t.Errorf("an uncolored head carries an escape: %q", plain)
	}
	if !strings.Contains(plain, " CRITICAL  /etc/ld.so.preload") {
		t.Errorf("the plain head misses its badge and object: %q", plain)
	}
	batch := []struct {
		severity Severity
		ground   int
		ink      int
	}{
		{Critical, 1, 15},
		{High, 9, 0},
		{Medium, 11, 0},
		{Low, 14, 15},
	}
	for _, test := range batch {
		head := findingHead(layoutFinding(test.severity, "judgment", "/etc/x"), 98, true)
		want := chrome.Bg(test.ground) + chrome.Fg(test.ink) + "\x1b[1m " +
			strings.ToUpper(test.severity.String()) + " "
		if !strings.Contains(head, want) {
			t.Errorf("%s badge = %q, want the ground %d and ink %d", test.severity, head, test.ground, test.ink)
		}
		if width := chrome.DisplayWidth(head); width > 98 {
			t.Errorf("%s head is %d columns wide: %q", test.severity, width, head)
		}
	}
	long := findingHead(layoutFinding(Low, "judgment", "/var/lib/vendor/runtime/.attach-loader.sh"), 40, false)
	if width := chrome.DisplayWidth(long); width > 40 {
		t.Errorf("a truncated head is %d columns wide: %q", width, long)
	}
}

func TestHighlightTokensPaintsPathsAndOrigins(t *testing.T) {
	line := "trigger /etc/ld.so.preload: runtime (created after the boundary)"
	painted := highlightTokens(line, mutedColor, true)
	for _, want := range []string{
		chrome.Fg(mutedColor) + "trigger",
		chrome.Fg(hueInformation) + "/etc/ld.so.preload",
		chrome.Fg(hueAlert) + "runtime",
	} {
		if !strings.Contains(painted, want) {
			t.Errorf("the line misses %q:\n%q", want, painted)
		}
	}
	if plain := highlightTokens(line, mutedColor, false); plain != line {
		t.Errorf("an uncolored line changed: %q", plain)
	}
	prose := highlightTokens("the base files stay quiet", mutedColor, true)
	if strings.Contains(prose, chrome.Fg(hueAlert)) || strings.Contains(prose, chrome.Fg(hueCaution)) ||
		strings.Contains(prose, chrome.Fg(hueProvisioned)) {
		t.Errorf("a prose origin word took a verdict hue: %q", prose)
	}
}

func TestFindingPanelsGroupOneObjectRelations(t *testing.T) {
	path := "/etc/ld.so.preload"
	first := Finding{
		Class: "activation-introduction", Severity: Critical,
		Title: "runtime object in an activation surface", Path: path,
		Origin: Runtime, Reach: RootAsset,
		Detail:   "first detail",
		Trace:    []Step{{Text: "profile"}, {Text: path}},
		Evidence: []string{"shared line", "first line"},
	}
	second := first
	second.Detail = "second detail"
	second.Evidence = []string{"shared line", "second line"}
	findings := []Finding{first, second}
	sortFindings(findings)
	groups := groupFindings(findings)
	if len(groups) != 1 || len(groups[0]) != 2 {
		t.Fatalf("panel groups = %v, want one group of two", groups)
	}
	plain := chrome.StripANSI(findingPanel(panelGroup{findings: groups[0]}, true, RenderOptions{}, 100))
	body := strings.Join(strings.Split(plain, "\n")[1:], "\n")
	for _, want := range []string{
		first.Title,
		"origin runtime · reach root",
		"· chain  profile → " + path,
		"· shared line", "· first line", "· second line",
		"· next  karma graph path:" + path,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the grouped panel misses %q:\n%s", want, body)
		}
	}
	for _, once := range []string{first.Title, "origin runtime · reach root", "· chain  profile → " + path, "· shared line"} {
		if n := strings.Count(body, once); n != 1 {
			t.Errorf("%q prints %d times, want once:\n%s", once, n, body)
		}
	}
	// Each member's relation is already in the chain; the per-relation
	// sentences do not repeat inside the group.
	for _, detail := range []string{"first detail", "second detail"} {
		if strings.Contains(body, detail) {
			t.Errorf("the grouped panel repeats the relation sentence %q:\n%s", detail, body)
		}
	}
}

func TestGroupedPanelDrawsASharedRootAsATree(t *testing.T) {
	path := "/etc/nsswitch.conf"
	member := func(hop string) Finding {
		return Finding{
			Class: "activation-introduction", Severity: Critical,
			Title: "runtime object in an activation surface", Path: path,
			Origin: Runtime, Reach: RootAsset, Detail: "nss " + hop,
			Trace: []Step{{Text: path}, {Text: hop}},
		}
	}
	findings := []Finding{member("libnss_one.so"), member("libnss_two.so"), member("libnss_three.so")}
	sortFindings(findings)
	groups := groupFindings(findings)
	if len(groups) != 1 || len(groups[0]) != 3 {
		t.Fatalf("panel groups = %v, want one group of three", groups)
	}
	plain := chrome.StripANSI(findingPanel(panelGroup{findings: groups[0]}, false, RenderOptions{}, 100))
	for _, want := range []string{
		"· chain  " + path,
		"         ├─ libnss_one.so",
		"         ├─ libnss_two.so",
		"         └─ libnss_three.so",
	} {
		if !strings.Contains(plain, want) {
			t.Errorf("the tree misses %q:\n%s", want, plain)
		}
	}
	if n := strings.Count(plain, "· chain  "); n != 1 {
		t.Errorf("the shared root prints %d times, want once:\n%s", n, plain)
	}
}

func TestGroupedPanelKeepsDistinctRootsFlat(t *testing.T) {
	member := func(root, hop string) Finding {
		return Finding{
			Class: "identity-sudo-nopasswd", Severity: Critical,
			Title: "passwordless sudo ALL", Path: "/etc/sudoers.d/90-lab-backdoor",
			Origin: Runtime, Reach: RootAsset, Detail: "account " + root,
			Trace: []Step{{Text: "account " + root}, {Text: hop}},
		}
	}
	findings := []Finding{member("www-data", "passwordless sudo ALL"), member("svc-backup", "passwordless sudo ALL")}
	sortFindings(findings)
	groups := groupFindings(findings)
	if len(groups) != 1 || len(groups[0]) != 2 {
		t.Fatalf("panel groups = %v, want one group of two", groups)
	}
	plain := chrome.StripANSI(findingPanel(panelGroup{findings: groups[0]}, false, RenderOptions{}, 100))
	for _, want := range []string{
		"· chain  account www-data → passwordless sudo ALL",
		"· chain  account svc-backup → passwordless sudo ALL",
	} {
		if !strings.Contains(plain, want) {
			t.Errorf("the flat chains miss %q:\n%s", want, plain)
		}
	}
	if strings.Contains(plain, "├─") || strings.Contains(plain, "└─") {
		t.Errorf("distinct roots were drawn as one tree:\n%s", plain)
	}
}

func TestFindingPanelsSplitClassesAndSeverities(t *testing.T) {
	sameClass := []Finding{
		layoutClassFinding(Critical, "activation-introduction", "first verdict", "/etc/x"),
		layoutClassFinding(Critical, "activation-writable", "second verdict", "/etc/x"),
	}
	sortFindings(sameClass)
	if groups := groupFindings(sameClass); len(groups) != 2 {
		t.Errorf("panel groups = %d, want one panel per class", len(groups))
	}
	splitSeverity := []Finding{
		layoutClassFinding(Critical, "test", "same verdict", "/etc/x"),
		layoutClassFinding(High, "test", "same verdict", "/etc/x"),
	}
	sortFindings(splitSeverity)
	if groups := groupFindings(splitSeverity); len(groups) != 2 {
		t.Errorf("panel groups = %d, want one panel per severity", len(groups))
	}
}

func TestPathlessFindingsNeverGroup(t *testing.T) {
	findings := []Finding{
		layoutFinding(Critical, "structural", ""),
		layoutFinding(Critical, "structural", ""),
	}
	sortFindings(findings)
	if groups := groupFindings(findings); len(groups) != 2 {
		t.Errorf("panel groups = %d, want one panel per pathless finding", len(groups))
	}
}

func TestGroupedPanelDedupesRepeatedLines(t *testing.T) {
	path := "/etc/ld.so.preload"
	member := func(detail string, evidence ...string) Finding {
		return Finding{
			Class: "activation-introduction", Severity: Critical,
			Title: "runtime object in an activation surface", Path: path,
			Origin: Runtime, Reach: RootAsset, Detail: detail,
			Trace:    []Step{{Text: "profile"}, {Text: path}},
			Evidence: evidence,
		}
	}
	findings := []Finding{
		member("same detail", "same evidence", "first evidence"),
		member("same detail", "same evidence", "second evidence"),
	}
	sortFindings(findings)
	groups := groupFindings(findings)
	if len(groups) != 1 || len(groups[0]) != 2 {
		t.Fatalf("panel groups = %v, want one group of two", groups)
	}
	plain := chrome.StripANSI(findingPanel(panelGroup{findings: groups[0]}, false, RenderOptions{}, 100))
	body := strings.Join(strings.Split(plain, "\n")[1:], "\n")
	for _, once := range []string{"same detail", "· same evidence", "origin runtime · reach root", "· chain  profile → " + path} {
		if n := strings.Count(body, once); n != 1 {
			t.Errorf("%q prints %d times, want once:\n%s", once, n, body)
		}
	}
	for _, line := range []string{"· first evidence", "· second evidence"} {
		if n := strings.Count(body, line); n != 1 {
			t.Errorf("%q prints %d times, want once:\n%s", line, n, body)
		}
	}
}

func TestFindingPanelKeepsTheHierarchy(t *testing.T) {
	path := "/etc/profile.d/vendor-runtime-loader.sh"
	finding := Finding{
		Severity: Critical,
		Title:    "runtime object in an activation surface",
		Path:     path,
		Origin:   Runtime,
		Reach:    RootAsset,
		Detail:   "export VENDOR_RUNTIME_LOADER in " + path + " activates the loader",
		Trace:    []Step{{Text: "profile"}, {Text: path}, {Text: "runtime"}},
		Evidence: []string{"no package owns it"},
	}
	plain := chrome.StripANSI(findingPanel(panelGroup{findings: findingGroup{finding}}, true, RenderOptions{}, 100))
	lines := strings.Split(plain, "\n")
	if !strings.Contains(lines[0], "CRITICAL  "+path) {
		t.Errorf("the head misses the badge or object: %q", lines[0])
	}
	want := []string{
		"▌  runtime object in an activation surface",
		"▌  export VENDOR_RUNTIME_LOADER in " + path + " activates the loader",
		"▌  origin runtime · reach root",
		"▌  · chain  profile → " + path + " → runtime",
		"▌  · no package owns it",
		"▌  · next  karma graph path:" + path,
	}
	body := lines[1:]
	if len(body) != len(want) {
		t.Fatalf("the panel body has %d lines, want %d:\n%s", len(body), len(want), plain)
	}
	for index := range want {
		if body[index] != want[index] {
			t.Errorf("body line %d = %q, want %q", index, body[index], want[index])
		}
	}
}

func TestFindingPanelWithoutAPathHasNoNextLine(t *testing.T) {
	finding := layoutFinding(Info, "structural only", "")
	plain := chrome.StripANSI(findingPanel(panelGroup{findings: findingGroup{finding}}, true, RenderOptions{}, 100))
	if strings.Contains(plain, "· next") {
		t.Errorf("a pathless finding offers a graph to open:\n%s", plain)
	}
}

func TestNextLineAppearsOnlyOnNarrowedRuns(t *testing.T) {
	finding := layoutFinding(Critical, "runtime object", "/etc/ld.so.preload")
	report := layoutReport([]Finding{finding})
	if text := renderText(t, report, RenderOptions{Width: 100}); strings.Contains(text, "· next") {
		t.Errorf("a bare report offers the graph:\n%s", text)
	}
	scoped := renderText(t, report, RenderOptions{Width: 100, Filter: Filter{Paths: []string{"/etc"}}})
	if n := strings.Count(scoped, "· next"); n != 1 {
		t.Errorf("a scoped report prints %d next lines, want one:\n%s", n, scoped)
	}
	view := &GraphView{Root: "path:" + finding.Path, Findings: []Finding{finding}}
	var out strings.Builder
	RenderGraph(&out, view, RenderOptions{Width: 100})
	if n := strings.Count(out.String(), "· next"); n != 1 {
		t.Errorf("a graph page prints %d next lines, want one:\n%s", n, out.String())
	}
}

func TestFilterNarrowed(t *testing.T) {
	cases := []struct {
		name   string
		filter Filter
		want   bool
	}{
		{"bare", Filter{}, false},
		{"surfaces", Filter{Surfaces: surfacePtr(startup.Systemd)}, true},
		{"paths", Filter{Paths: []string{"/etc"}}, true},
		{"excluded paths", Filter{ExcludePaths: []string{"/tmp"}}, true},
		{"pids", Filter{PIDs: map[int]bool{1: true}}, true},
		{"units", Filter{Units: map[string]bool{"ssh.service": true}}, true},
		{"off domains", Filter{Domains: AllDomains &^ DomainKernel}, true},
	}
	for _, test := range cases {
		if got := test.filter.narrowed(); got != test.want {
			t.Errorf("%s: narrowed = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestSortFindingsOrdersSeverityPathClass(t *testing.T) {
	findings := []Finding{
		{Severity: Low, Path: "/b", Class: "a"},
		{Severity: Critical, Path: "/b", Class: "b"},
		{Severity: High, Path: "/a", Class: "a"},
		{Severity: Critical, Path: "/a", Class: "b"},
		{Severity: Critical, Path: "/a", Class: "a"},
	}
	sortFindings(findings)
	want := []struct {
		severity Severity
		path     string
		class    string
	}{
		{Critical, "/a", "a"},
		{Critical, "/a", "b"},
		{Critical, "/b", "b"},
		{High, "/a", "a"},
		{Low, "/b", "a"},
	}
	for index, expected := range want {
		got := findings[index]
		if got.Severity != expected.severity || got.Path != expected.path || string(got.Class) != expected.class {
			t.Errorf("finding %d = %s %s %s, want %s %s %s", index,
				got.Severity, got.Path, got.Class, expected.severity, expected.path, expected.class)
		}
	}
}

func TestFindingBodyWrapsProseWithoutCuttingTokens(t *testing.T) {
	path := "/var/lib/vendor/runtime/.attach-loader.sh"
	finding := Finding{
		Severity: Critical,
		Title:    "runtime object in an activation surface",
		Path:     "/etc/profile.d/vendor-runtime-loader.sh",
		Origin:   Runtime,
		Reach:    RootAsset,
		Detail:   "export VENDOR_RUNTIME_LOADER in /etc/profile.d/vendor-runtime-loader.sh activates " + path,
		Trace: []Step{
			{Text: "profile"},
			{Text: "/etc/profile.d/vendor-runtime-loader.sh"},
			{Text: path},
			{Text: "runtime"},
		},
		Evidence: []string{
			"trigger /etc/profile.d/vendor-runtime-loader.sh: runtime (created after the boundary); " +
				"payload /var/lib/vendor/runtime/.attach-loader.sh timestamp 2026-11-25T06:33:28",
		},
	}
	panel := findingPanel(panelGroup{findings: findingGroup{finding}}, true, RenderOptions{Color: true}, 80)
	lines := strings.Split(panel, "\n")
	for index, line := range lines {
		if width := chrome.DisplayWidth(line); width > 80 {
			t.Errorf("line %d is %d columns wide: %q", index, width, line)
		}
	}
	plain := chrome.StripANSI(panel)
	for _, token := range []string{
		"/var/lib/vendor/runtime/.attach-loader.sh",
		"2026-11-25T06:33:28",
	} {
		if !strings.Contains(plain, token) {
			t.Errorf("the token %q was cut mid-word:\n%s", token, plain)
		}
	}
	if !strings.Contains(plain, "\n▌    ") {
		t.Errorf("a wrapped line carries no hanging indent:\n%s", plain)
	}
}

func TestQuoteRowsGroupByPathAndAlignNumbers(t *testing.T) {
	quotes := []Quote{
		{Path: "/etc/sudoers", Line: 1, Text: "www-data ALL=(ALL) NOPASSWD: ALL"},
		{Path: "/etc/sudoers", Line: 10, Text: "root ALL=(ALL) ALL"},
		{Path: "/etc/passwd", Line: 7, Text: "svc:x:0:0::/root:/bin/bash"},
		{Path: "/etc/tmp", Line: 0, Text: "flag=1"},
		{Path: "/etc/sudoers", Line: 1, Text: "www-data ALL=(ALL) NOPASSWD: ALL"},
	}
	rows := quoteRows(findingGroup{{Quotes: quotes}}, false)
	want := []string{
		"· cite  /etc/sudoers",
		"         1 │ www-data ALL=(ALL) NOPASSWD: ALL",
		"        10 │ root ALL=(ALL) ALL",
		"· cite  /etc/passwd",
		"        7 │ svc:x:0:0::/root:/bin/bash",
		"· cite  /etc/tmp  flag=1",
	}
	if len(rows) != len(want) {
		t.Fatalf("quote rows = %d, want %d:\n%s", len(rows), len(want), strings.Join(rows, "\n"))
	}
	for index := range want {
		if rows[index] != want[index] {
			t.Errorf("row %d = %q, want %q", index, rows[index], want[index])
		}
	}
}

func TestFindingPanelCitesItsSourceLines(t *testing.T) {
	path := "/etc/ld.so.preload"
	quote := Quote{Path: path, Line: 2, Text: "preload /var/lib/vendor/runtime/.attach-loader.sh"}
	first := layoutFinding(Critical, "runtime object in an activation surface", path)
	first.Quotes = []Quote{quote}
	second := first
	second.Detail = "second relation"
	findings := []Finding{first, second}
	sortFindings(findings)
	groups := groupFindings(findings)
	panel := findingPanel(panelGroup{findings: groups[0]}, false, RenderOptions{Color: true}, 80)
	plain := chrome.StripANSI(panel)
	if n := strings.Count(plain, "· cite  "+path); n != 1 {
		t.Errorf("the cited path prints %d headers, want one:\n%s", n, plain)
	}
	if !strings.Contains(plain, "2 │ preload /var/lib/vendor/runtime/.attach-loader.sh") {
		t.Errorf("the quote line is missing:\n%s", plain)
	}
	if !strings.Contains(panel, chrome.Fg(hueInformation)+path) {
		t.Errorf("the cited path lost its information hue:\n%s", panel)
	}
	if !strings.Contains(panel, chrome.Fg(mutedColor)+" │ ") {
		t.Errorf("the quote bar is not muted:\n%s", panel)
	}
	if strings.Contains(panel, chrome.Fg(mutedColor)+"preload") {
		t.Errorf("the quoted text is painted like evidence:\n%s", panel)
	}
	for index, line := range strings.Split(panel, "\n") {
		if width := chrome.DisplayWidth(line); width > 80 {
			t.Errorf("line %d is %d columns wide: %q", index, width, line)
		}
	}
}

func TestQuoteLineWrapsProse(t *testing.T) {
	path := "/etc/ld.so.preload"
	text := "preload /var/lib/vendor/runtime/.attach-loader.sh and keep the whole path readable"
	quote := Quote{Path: path, Line: 4, Text: text}
	finding := layoutFinding(Critical, "runtime object", path)
	finding.Quotes = []Quote{quote}
	panel := findingPanel(panelGroup{findings: findingGroup{finding}}, false, RenderOptions{}, 72)
	for index, line := range strings.Split(panel, "\n") {
		if width := chrome.DisplayWidth(line); width > 72 {
			t.Errorf("line %d is %d columns wide: %q", index, width, line)
		}
	}
	if !strings.Contains(chrome.StripANSI(panel), "/var/lib/vendor/runtime/.attach-loader.sh") {
		t.Errorf("a cited token was cut mid-word:\n%s", chrome.StripANSI(panel))
	}
}
