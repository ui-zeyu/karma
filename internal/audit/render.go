package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	chrome "karma/internal/panel"
)

// RenderOptions carries what the report needs to read well on this stream.
type RenderOptions struct {
	Version  string
	Color    bool
	Evidence bool
	Width    int
	Filter   Filter
	// Root is the object a graph page is about; a finding on that object
	// already has the page it would open.
	Root string
}

// The report's chrome, the palette the old surface used: a dark level-one
// band, a lighter level-two band, muted grey, and the severity hues. The
// drawing primitives live in internal/panel, shared with the CLI's help
// screens; the names stay local so the report reads as before.
const (
	bannerBG   = chrome.BannerBG
	bannerFG   = chrome.BannerFG
	subBandBG  = chrome.SubBandBG
	subBandFG  = chrome.SubBandFG
	mutedColor = chrome.MutedColor
	ansiReset  = chrome.Reset
)

// The semantic hues the evidence tables share: the warm pair states a live
// anomaly and a caution, the pale pair a provisioned object and a healthy
// state, and the cool pair information and a transition.
const (
	hueAlert       = 203
	hueCaution     = 214
	hueProvisioned = 110
	hueLive        = 2
	hueFailed      = 1
	hueTransition  = 3
	hueInformation = 6
)

var (
	band         = chrome.Band
	rail         = chrome.Rail
	paintText    = chrome.Paint
	fg           = chrome.Fg
	bg           = chrome.Bg
	displayWidth = chrome.DisplayWidth
	truncate     = chrome.Truncate
)

// Render writes the audit as the operator's worksheet: masthead, findings,
// the raw inventories behind them, and coverage.
func Render(w io.Writer, report *Report, options RenderOptions) {
	width := reportWidth(options.Width)
	renderMasthead(w, report, options, width)
	if len(report.Findings) == 0 {
		body := "no findings: the artifact delta is empty and no activation path is writable"
		if report.Kernel != nil {
			body = "no findings: the artifact delta, activation surfaces and kernel state are clean"
		}
		if report.Boundary.Time.IsZero() {
			body = "no findings: the boundary is unknown, so only structural checks ran"
		}
		fmt.Fprintln(w, rail(band(" QUIET", "", width-2, subBandBG, subBandFG, false, options.Color),
			[]string{body}, width, mutedColor, options.Color))
		fmt.Fprintln(w)
	}
	next := options.Filter.narrowed()
	for _, group := range panelGroups(report.Findings, options.Filter) {
		fmt.Fprintln(w, findingPanelDir(group.findings, group.dir, group.files, next, options, width))
		fmt.Fprintln(w)
	}
	if options.Evidence && report.view != nil {
		renderEvidence(w, report.view, options, width)
	}
	if len(report.Coverage) > 0 {
		coverage := make([]string, len(report.Coverage))
		for index, line := range report.Coverage {
			coverage[index] = chrome.SafeText(line)
		}
		fmt.Fprintln(w, evidencePanel("COVERAGE", coverage, len(coverage), options, width))
	}
}

// renderEvidence prints the raw inventories behind the findings: one panel
// per evidence type, each capped so a whole-surface run still reads as a
// worksheet. The full inventory is `karma show <section>`.
func renderEvidence(w io.Writer, view *View, options RenderOptions, width int) {
	fmt.Fprintln(w, band(" EVIDENCE", "", width, bannerBG, bannerFG, true, options.Color))
	for _, section := range sections {
		if section.SkipEvidence {
			continue
		}
		rows := sectionRows(section, view, options)
		if len(rows) > 0 {
			fmt.Fprintln(w, evidencePanel(section.Panel, cappedRows(rows, options),
				section.Count(view, options), options, width))
		}
	}
}

// evidenceLimit is the rows one evidence panel prints. The rest folds into a
// note that names the narrower answer; `karma show <section>` prints every
// row uncapped.
const evidenceLimit = 200

func cappedRows(rows []string, options RenderOptions) []string {
	if len(rows) <= evidenceLimit {
		return rows
	}
	shown := append([]string(nil), rows[:evidenceLimit]...)
	return append(shown, paintText(options.Color, fg(mutedColor),
		fmt.Sprintf("... %d more; narrow the scope or use show", len(rows)-evidenceLimit)))
}

func evidencePanel(title string, rows []string, count int, options RenderOptions, width int) string {
	head := band(" "+title, strconv.Itoa(count)+" ", width-2, subBandBG, subBandFG, false, options.Color)
	return rail(head, rows, width, mutedColor, options.Color)
}

func sectionRows(section *Section, view *View, options RenderOptions) []string {
	rows := section.Rows(view, options)
	if !section.Plain {
		return rows
	}
	safe := make([]string, len(rows))
	for index, row := range rows {
		safe[index] = chrome.SafeText(row)
	}
	return safe
}

// RenderShow prints one raw inventory in the page language every command
// wears: the karma masthead with the run's context, then the section's
// canonical panel with every row it collected.
func RenderShow(w io.Writer, view *View, section *Section, word string, options RenderOptions) {
	width := reportWidth(options.Width)
	writeMasthead(w, options, width, []fact{
		{label: "section", value: word},
		{label: "host", value: valueOr(view.Snapshot.Host.Hostname, "unknown")},
		{label: "boundary", value: boundaryText(view.Snapshot.Boundary), full: true},
	}, nil)
	rows := sectionRows(section, view, options)
	collected := 0
	if section.Plain {
		collected = len(rows)
	} else {
		collected = section.Count(view, options)
	}
	if len(rows) == 0 {
		rows = []string{"nothing in this section answers the selected scope"}
	}
	fmt.Fprintln(w, evidencePanel(section.Panel, rows, collected, options, width))
}

// WriteShowJSON writes one show section as data: the section's word and its
// collected structures under the section's own key. The text rows stay a
// terminal view; the JSON answer is the inventory itself, so a column the
// text gains or loses cannot change the machine answer's shape.
func WriteShowJSON(w io.Writer, view *View, section *Section, word string, options RenderOptions) error {
	payload := map[string]any{
		"section":       word,
		section.JSONKey: section.Data(view, options),
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}

func writeMasthead(w io.Writer, options RenderOptions, width int, facts []fact, extra []string) {
	fmt.Fprintln(w, band(" KARMA", byline(), width, bannerBG, bannerFG, true, options.Color))
	head := band(" "+versionText(options), clock(), width-2, subBandBG, subBandFG, false, options.Color)
	body := factGrid(facts, width-4)
	body = append(body, extra...)
	fmt.Fprintln(w, rail(head, body, width, mutedColor, options.Color))
	fmt.Fprintln(w)
}

func renderMasthead(w io.Writer, report *Report, options RenderOptions, width int) {
	modules := 0
	trail := 0
	if report.view != nil {
		modules = kernelCount(report.view, options)
		trail = len(report.view.Trail)
	}
	facts := []fact{
		{label: "host", value: valueOr(report.Host.Hostname, "unknown")},
		{label: "distro", value: valueOr(report.Host.OS, "unknown distro")},
		{label: "account", value: accountCell(report.Host)},
		{label: "kernel", value: valueOr(report.Host.Kernel, "unknown")},
		{label: "source", value: valueOr(report.Source, "unknown")},
	}
	if len(report.OffDomains) > 0 {
		// A scoped run's quiet is only about the domains it judged; the
		// masthead names the ones that stayed off.
		facts = append(facts, fact{label: "off domains", value: strings.Join(report.OffDomains, ", "), full: true})
	}
	facts = append(facts,
		fact{label: "ledger", value: ledgerCell(report.Ledger), full: true},
		fact{label: "boundary", value: boundaryText(report.Boundary), full: true},
		fact{label: "read", value: fmt.Sprintf("%d edges · %d proc · %d auth · %d svc · %d listen · %d mod · %d trail",
			report.Activated, report.Processes, len(report.AuthorityObjects), len(report.Services), len(report.Sockets), modules, trail), full: true},
	)
	labelWidth := factLabelWidth(facts)
	if len("findings") > labelWidth {
		labelWidth = len("findings")
	}
	writeMasthead(w, options, width, facts,
		findingsFact(report.Findings, labelWidth, width-4, options.Color))
}

func byline() string {
	if user := os.Getenv("USER"); user != "" {
		return chrome.SafeText(user) + " "
	}
	return "karma "
}

func versionText(options RenderOptions) string {
	if options.Version != "" {
		return options.Version
	}
	return "dev"
}

func clock() string { return time.Now().Format("2006-01-02 15:04:05 -0700") }

func boundaryText(boundary Boundary) string {
	if boundary.Time.IsZero() {
		return "unknown"
	}
	switch boundary.Source {
	case "operator":
		return "operator boundary " + boundary.Time.Format(stampLayout)
	case "package":
		return "package boundary " + boundary.Time.Format(stampLayout)
	}
	return boundary.Kind + " start " + boundary.Time.Format(stampLayout)
}

// ledgerCell reads the content ledger for the masthead: which ledger answered
// and how far it reached.
func ledgerCell(summary LedgerSummary) string {
	switch summary.Kind {
	case "", "none":
		return "none"
	}
	cell := fmt.Sprintf("%s · %d pkgs · %s checked · %d verified",
		summary.Kind, summary.Packages, compactCount(summary.Entries), summary.Verified)
	if summary.Mismatched > 0 {
		cell += fmt.Sprintf(" · %d deviated", summary.Mismatched)
	}
	if len(summary.Tampered) > 0 {
		cell += fmt.Sprintf(" · %d tampered", len(summary.Tampered))
	}
	return cell
}

// compactCount prints a number in thousands units, the only scale the ledger
// reaches.
func compactCount(value int) string {
	if value >= 1000 {
		return fmt.Sprintf("%.1fk", float64(value)/1000)
	}
	return strconv.Itoa(value)
}

func reportWidth(width int) int {
	if width < 60 {
		return 100
	}
	return width
}

type fact struct {
	label string
	value string
	full  bool
}

// factGrid lays two facts to a row while the line has room, one otherwise.
// Each cell is label + value; the two cells and the gap between them fit the
// body width exactly, so a long value cannot push the right cell off the rail.
func factGrid(facts []fact, width int) []string {
	labelWidth := factLabelWidth(facts)
	column := (width - 2*(labelWidth+2) - 2) / 2
	if column < 16 {
		column = 0
	}
	cell := func(f fact, valueWidth int) string {
		value := chrome.SafeText(f.value)
		return fmt.Sprintf("%-*s  %s", labelWidth, f.label, truncate(value, valueWidth))
	}
	cellWidth := labelWidth + 2 + column
	var lines []string
	for index := 0; index < len(facts); index++ {
		if facts[index].full || column == 0 || index+1 >= len(facts) || facts[index+1].full {
			lines = append(lines, cell(facts[index], width-labelWidth-2))
			continue
		}
		left := fmt.Sprintf("%-*s", cellWidth, cell(facts[index], column))
		right := cell(facts[index+1], column)
		lines = append(lines, left+"  "+right)
		index++
	}
	return lines
}

func factLabelWidth(facts []fact) int {
	labelWidth := 0
	for _, f := range facts {
		if n := displayWidth(f.label); n > labelWidth {
			labelWidth = n
		}
	}
	return labelWidth
}

func accountCell(host Host) string {
	switch {
	case host.UID == 0:
		return "root (uid 0)"
	case host.UID > 0:
		return fmt.Sprintf("uid %d", host.UID)
	}
	return ""
}

// findingsFact is the masthead's count line: every severity the run found,
// in the order the report ranks them, each in the badge its panel head wears.
func findingsFact(findings []Finding, labelWidth, width int, color bool) []string {
	prefix := fmt.Sprintf("%-*s  ", labelWidth, "findings")
	if len(findings) == 0 {
		return []string{prefix + "none"}
	}
	counts := make(map[Severity]int, len(findings))
	for _, finding := range findings {
		counts[finding.Severity]++
	}
	tokens := []string{strconv.Itoa(len(findings))}
	for _, severity := range []Severity{Critical, High, Medium, Low, Info} {
		if counts[severity] == 0 {
			continue
		}
		text := fmt.Sprintf(" %d %s ", counts[severity], severity)
		tokens = append(tokens, severityBadge(severity, text, color))
	}
	indent := strings.Repeat(" ", labelWidth+2)
	lines := make([]string, 0, 2)
	line := prefix
	for index, token := range tokens {
		if index == 0 {
			line += token
			continue
		}
		if displayWidth(line+" · "+token) > width {
			lines = append(lines, line)
			line = indent + token
			continue
		}
		line += " · " + token
	}
	return append(lines, line)
}

// findingGroup is a maximal run of findings that describe one object at one
// severity, class and title; one panel prints the run.
type findingGroup []Finding

func groupFindings(findings []Finding) []findingGroup {
	return groupRuns(findings, func(left, right Finding) bool {
		return left.Path != "" && left.Path == right.Path &&
			left.Class == right.Class && left.Severity == right.Severity && left.Title == right.Title
	})
}

// groupRuns folds the report's runs of like findings into panel groups.
func groupRuns(findings []Finding, same func(left, right Finding) bool) []findingGroup {
	var groups []findingGroup
	for _, finding := range findings {
		if n := len(groups); n > 0 && same(groups[n-1][0], finding) {
			groups[n-1] = append(groups[n-1], finding)
			continue
		}
		groups = append(groups, findingGroup{finding})
	}
	return groups
}

// directoryRollupThreshold is the number of distinct files in one directory
// that turns a wall of single-file panels into one directory panel. The limit
// is the sample a rolled-up panel names; the rest stay one command away.
const (
	directoryRollupThreshold = 6
	directoryRollupLimit     = 8
)

// panelGroup is one printed finding panel. dir is set when the panel rolls a
// directory's same-judgment findings up; the JSON and the filtered report
// still carry every finding.
type panelGroup struct {
	findings findingGroup
	dir      string
	files    int
}

type rollupKey struct {
	dir      string
	class    string
	title    string
	severity Severity
}

// panelGroups folds the exact-object groups into directory panels where a
// directory holds enough files with one judgment. A scope that names the
// directory itself keeps every file visible, so the rollup has a way back.
func panelGroups(findings []Finding, filter Filter) []panelGroup {
	groups := groupFindings(findings)
	buckets := map[rollupKey][]findingGroup{}
	files := map[rollupKey]map[string]bool{}
	for _, group := range groups {
		if group[0].Path == "" {
			continue
		}
		dir := filepath.Dir(group[0].Path)
		if dir == "/" || dir == "." {
			continue
		}
		key := rollupKey{dir: dir, class: group[0].Class, title: group[0].Title, severity: group[0].Severity}
		buckets[key] = append(buckets[key], group)
		if files[key] == nil {
			files[key] = map[string]bool{}
		}
		for _, member := range group {
			files[key][member.Path] = true
		}
	}
	rolled := map[rollupKey]string{}
	for key, set := range files {
		if len(set) < directoryRollupThreshold {
			continue
		}
		if len(filter.Paths) > 0 && pathInScope(key.dir, filter) {
			continue
		}
		// A rollup states one judgment over many files. When the files carry
		// different sentences (different triggers, hashes or process ids),
		// each file remains its own panel; a directory head would hide the
		// distinction the details state.
		detail := buckets[key][0][0].Detail
		sameDetail := true
		for _, bucket := range buckets[key] {
			for _, member := range bucket {
				if member.Detail != detail {
					sameDetail = false
					break
				}
			}
		}
		if !sameDetail {
			continue
		}
		rolled[key] = key.dir
	}
	emitted := map[rollupKey]bool{}
	out := make([]panelGroup, 0, len(groups))
	for _, group := range groups {
		if group[0].Path == "" {
			out = append(out, panelGroup{findings: group})
			continue
		}
		key := rollupKey{
			dir: filepath.Dir(group[0].Path), class: group[0].Class,
			title: group[0].Title, severity: group[0].Severity,
		}
		dir, ok := rolled[key]
		if !ok {
			out = append(out, panelGroup{findings: group})
			continue
		}
		if emitted[key] {
			continue
		}
		emitted[key] = true
		var members findingGroup
		for _, bucket := range buckets[key] {
			members = append(members, bucket...)
		}
		out = append(out, panelGroup{findings: members, dir: dir, files: len(files[key])})
	}
	return out
}

// findingPanel draws one group: the head names the object and its severity,
// the body states the verdict, the relation and the facts behind it.
func findingPanel(group findingGroup, next bool, options RenderOptions, width int) string {
	return findingPanelDir(group, "", 0, next, options, width)
}

func findingPanelDir(group findingGroup, dir string, files int, next bool, options RenderOptions, width int) string {
	if dir != "" {
		return findingRollup(group, dir, files, options, width)
	}
	finding := group[0]
	head := findingHead(finding, width-2, options.Color)
	var body []string
	seen := make(map[string]bool, len(group))
	add := func(line string) {
		if line == "" || seen[line] {
			return
		}
		seen[line] = true
		body = append(body, line)
	}
	add(paintText(options.Color, "\x1b[1m", chrome.SafeText(finding.Title)))
	if len(group) == 1 {
		add(highlightTokens(finding.Detail, 0, options.Color))
	} else {
		// A group states its relations once: identical details print once,
		// and a member whose chain already carries the relation drops its
		// per-relation sentence.
		shared := group[0].Detail
		for _, member := range group[1:] {
			if member.Detail != shared {
				shared = ""
				break
			}
		}
		add(highlightTokens(shared, 0, options.Color))
		for _, member := range group {
			if len(member.Trace) == 0 {
				add(highlightTokens(member.Detail, 0, options.Color))
			}
		}
	}
	for _, member := range group {
		add(paintText(options.Color, fg(mutedColor), "origin ") +
			paintText(options.Color, fg(originHue(member.Origin)), member.Origin.String()) +
			paintText(options.Color, fg(mutedColor), " · reach "+member.Reach.String()))
	}
	for _, line := range chainRows(group, options.Color) {
		add(line)
	}
	for _, member := range group {
		for _, line := range member.Evidence {
			add(paintText(options.Color, fg(mutedColor), "· ") + highlightTokens(line, mutedColor, options.Color))
		}
	}
	for _, line := range quoteRows(group, options.Color) {
		// A citation block's header names the file; two accounts' histories
		// can quote the same text, and both blocks stay readable.
		if line != "" {
			body = append(body, line)
		}
	}
	if next && finding.Path != "" && finding.Path != options.Root {
		add(paintText(options.Color, fg(mutedColor), "· next  ") + "karma graph path:" + finding.Path)
	}
	return chrome.RailText(head, body, width, severityColor(finding.Severity), options.Color)
}

// findingRollup draws a directory's same-judgment findings as one panel. The
// head is the directory, the body samples the files, and the rest stay one
// narrowed audit away; JSON and the per-file report are unchanged.
func findingRollup(group findingGroup, dir string, files int, options RenderOptions, width int) string {
	finding := group[0]
	headFinding := finding
	headFinding.Path = dir
	head := findingHead(headFinding, width-2, options.Color)
	var body []string
	seen := make(map[string]bool, len(group)+2)
	add := func(line string) {
		if line == "" || seen[line] {
			return
		}
		seen[line] = true
		body = append(body, line)
	}
	add(paintText(options.Color, "\x1b[1m", chrome.SafeText(finding.Title)))
	add(paintText(options.Color, fg(mutedColor),
		fmt.Sprintf("%d files in this directory carry the same judgment", files)))
	shared := group[0].Detail
	for _, member := range group[1:] {
		if member.Detail != shared {
			shared = ""
			break
		}
	}
	add(highlightTokens(shared, 0, options.Color))
	origins := make(map[string]bool, len(group))
	for _, member := range group {
		line := paintText(options.Color, fg(mutedColor), "origin ") +
			paintText(options.Color, fg(originHue(member.Origin)), member.Origin.String()) +
			paintText(options.Color, fg(mutedColor), " · reach "+member.Reach.String())
		if !origins[line] {
			origins[line] = true
			add(line)
		}
	}
	shown := 0
	seenPath := make(map[string]bool, files)
	for _, member := range group {
		if seenPath[member.Path] {
			continue
		}
		if shown == directoryRollupLimit {
			break
		}
		seenPath[member.Path] = true
		shown++
		row := paintText(options.Color, fg(mutedColor), "· ") + chrome.SafeText(filepath.Base(member.Path))
		if shared == "" && member.Detail != "" {
			row += "  " + highlightTokens(member.Detail, mutedColor, options.Color)
		}
		add(row)
	}
	if files > shown {
		add(paintText(options.Color, fg(mutedColor),
			fmt.Sprintf("... %d more files; karma audit %s", files-shown, dir)))
	}
	add(paintText(options.Color, fg(mutedColor), "· next  ") + "karma audit " + dir)
	return chrome.RailText(head, body, width, severityColor(finding.Severity), options.Color)
}

// quoteRows renders a group's source lines as citation blocks: every path
// gets one header, and its line numbers hang under it. Grouping by path
// (rather than by the adjacent run) keeps a source line and the trail lines
// that name the same object in one block.
type quoteBlock struct {
	path     string
	plain    []Quote
	numbered []Quote
}

func quoteRows(group findingGroup, color bool) []string {
	seen := make(map[Quote]bool, len(group))
	blocks := make([]quoteBlock, 0, len(group))
	index := make(map[string]int, len(group))
	addQuote := func(quote Quote) {
		if quote.Path == "" || quote.Text == "" || seen[quote] {
			return
		}
		seen[quote] = true
		at, ok := index[quote.Path]
		if !ok {
			at = len(blocks)
			index[quote.Path] = at
			blocks = append(blocks, quoteBlock{path: quote.Path})
		}
		if quote.Line == 0 {
			blocks[at].plain = append(blocks[at].plain, quote)
			return
		}
		blocks[at].numbered = append(blocks[at].numbered, quote)
	}
	for _, member := range group {
		for _, quote := range member.Quotes {
			addQuote(quote)
		}
	}
	var rows []string
	for _, block := range blocks {
		head := paintText(color, fg(mutedColor), "· cite  ") + highlightTokens(block.path, 0, color)
		for _, quote := range block.plain {
			rows = append(rows, head+"  "+highlightTokens(quote.Text, 0, color))
		}
		if len(block.numbered) == 0 {
			continue
		}
		rows = append(rows, head)
		width := 0
		for _, quote := range block.numbered {
			width = max(width, len(strconv.Itoa(quote.Line)))
		}
		indent := strings.Repeat(" ", displayWidth("· cite  "))
		for _, quote := range block.numbered {
			number := paintText(color, fg(mutedColor), fmt.Sprintf("%*d", width, quote.Line))
			rows = append(rows, indent+number+
				paintText(color, fg(mutedColor), " │ ")+highlightTokens(quote.Text, 0, color))
		}
	}
	return rows
}

// chainRows renders a group's relation paths: when every chain leaves the
// same root, the root prints once and the hops hang under it as a tree;
// otherwise each chain stays a flat arrow line.
func chainRows(group findingGroup, color bool) []string {
	label := paintText(color, fg(mutedColor), "· chain  ")
	var chains [][]string
	seen := make(map[string]bool, len(group))
	for _, member := range group {
		steps := traceTexts(member.Trace)
		if len(steps) == 0 {
			continue
		}
		key := strings.Join(steps, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		chains = append(chains, steps)
	}
	if len(chains) == 0 {
		return nil
	}
	if len(chains) > 1 && sharedRoot(chains) {
		rows := []string{label + highlightTokens(chains[0][0], 0, color)}
		indent := strings.Repeat(" ", displayWidth("· chain  "))
		var branches []string
		for _, chain := range chains {
			if rest := strings.Join(chain[1:], " → "); rest != "" {
				branches = append(branches, highlightTokens(rest, 0, color))
			}
		}
		for index, branch := range branches {
			mark := "├─ "
			if index == len(branches)-1 {
				mark = "└─ "
			}
			rows = append(rows, indent+paintText(color, fg(mutedColor), mark)+branch)
		}
		return rows
	}
	rows := make([]string, 0, len(chains))
	for _, chain := range chains {
		steps := make([]string, len(chain))
		for index, step := range chain {
			steps[index] = highlightTokens(step, 0, color)
		}
		rows = append(rows, label+strings.Join(steps, paintText(color, fg(mutedColor), " → ")))
	}
	return rows
}

// sharedRoot reports whether every chain starts at the same step.
func sharedRoot(chains [][]string) bool {
	for _, chain := range chains[1:] {
		if chain[0] != chains[0][0] {
			return false
		}
	}
	return true
}

// findingHead draws the severity as a filled badge beside the object it
// judges. The badge carries the severity hue as a ground, so the worst
// finding reads by shape before its color is compared.
func findingHead(finding Finding, width int, color bool) string {
	label := " " + strings.ToUpper(finding.Severity.String()) + " "
	path := " " + chrome.SafeText(finding.Path)
	if displayWidth(label+path) > width {
		path = " " + truncate(chrome.SafeText(finding.Path), width-displayWidth(label)-1)
	}
	plain := label + path
	fill := width - displayWidth(plain)
	if fill < 0 {
		fill = 0
	}
	if !color {
		return strings.TrimRight(plain+strings.Repeat(" ", fill), " ")
	}
	return severityBadge(finding.Severity, label, true) +
		bg(subBandBG) + fg(subBandFG) + path + strings.Repeat(" ", fill) + ansiReset
}

// severityBadge is the one severity ground/ink/weight: the masthead chips and
// every panel head read the same, so a palette change cannot split them.
func severityBadge(severity Severity, text string, color bool) string {
	return paintText(color, bg(severityColor(severity))+fg(badgeText(severity))+"\x1b[1m", text)
}

// badgeText is the ink the severity badge reads in: white on the deep ground
// of critical and low, black on the bright high and medium grounds.
func badgeText(severity Severity) int {
	switch severity {
	case Critical, Low:
		return 15
	}
	return 0
}

// processCount is the number of process rows the panel prints: the kernel's
// pid 0 and karma's own process carry no finding.
func processCount(view *View, _ RenderOptions) int {
	count := 0
	for _, process := range view.Processes {
		if process.PID == 0 || process.PID == selfPID() {
			continue
		}
		count++
	}
	return count
}

// kernelCount is the number of module-state rows, excluding the column head.
func kernelCount(view *View, _ RenderOptions) int {
	state := view.Kernel
	if state == nil || !state.Collected {
		return 0
	}
	count := 0
	scoped := !view.Filter.globalScope()
	for _, module := range state.Modules {
		if scoped && (module.File == "" || !pathOrRealInScope(module.File, module.Facts.Real, view.Filter)) {
			continue
		}
		count++
	}
	if !scoped {
		count += len(state.Dormant) + len(state.Hidden) + len(state.HiddenPIDs)
		if state.Tainted != 0 {
			count++
		}
		if len(state.LoaderDirs) > 0 {
			count++
		}
	}
	return count
}
