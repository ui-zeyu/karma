package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	chrome "karma/internal/panel"
)

// RenderOptions carries what the report needs to read well on this stream.
type RenderOptions struct {
	Version  string
	Color    bool
	Evidence bool
	Width    int
	Filter   Filter
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
	for _, group := range groupFindings(report.Findings) {
		fmt.Fprintln(w, findingPanel(group, next, options, width))
		fmt.Fprintln(w)
	}
	if options.Evidence && report.view != nil {
		renderEvidence(w, report.view, options, width)
	}
	if len(report.Coverage) > 0 {
		fmt.Fprintln(w, evidencePanel("COVERAGE", report.Coverage, len(report.Coverage), options, width))
	}
}

// renderEvidence prints the raw inventories behind the findings: one panel
// per evidence type, each capped so a whole-surface run still reads as a
// worksheet. The full inventory is `karma show <section>`.
func renderEvidence(w io.Writer, view *View, options RenderOptions, width int) {
	fmt.Fprintln(w, band(" EVIDENCE", "", width, bannerBG, bannerFG, true, options.Color))
	for _, section := range viewPanels(view, options) {
		if len(section.rows) > 0 {
			fmt.Fprintln(w, evidencePanel(section.title, cappedRows(section.rows, options),
				section.count(len(section.rows)), options, width))
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

// RenderShow prints one raw inventory in the page language every command
// wears: the karma masthead with the run's context, then the section's
// canonical panel with every row it collected.
func RenderShow(w io.Writer, view *View, section *Section, word string, options RenderOptions) {
	width := reportWidth(options.Width)
	fmt.Fprintln(w, band(" KARMA", "yuyy ", width, bannerBG, bannerFG, true, options.Color))
	head := band(" "+versionText(options), clock(), width-2, subBandBG, subBandFG, false, options.Color)
	facts := []fact{
		{label: "section", value: word},
		{label: "host", value: valueOr(view.Snapshot.Host.Hostname, "unknown")},
		{label: "boundary", value: boundaryText(view.Snapshot.Boundary), full: true},
	}
	fmt.Fprintln(w, rail(head, factGrid(facts, width-2), width, mutedColor, options.Color))
	fmt.Fprintln(w)
	rows, count := section.Rows(view, options)
	if len(rows) == 0 {
		rows = []string{"nothing in this section answers the selected scope"}
	}
	fmt.Fprintln(w, evidencePanel(section.Panel, rows, count(len(rows)), options, width))
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

func renderMasthead(w io.Writer, report *Report, options RenderOptions, width int) {
	fmt.Fprintln(w, band(" KARMA", "yuyy ", width, bannerBG, bannerFG, true, options.Color))
	head := band(" "+versionText(options), clock(), width-2, subBandBG, subBandFG, false, options.Color)
	modules := 0
	if report.Kernel != nil {
		modules = len(report.Kernel.Modules)
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
		fact{label: "judged", value: fmt.Sprintf("%d edges · %d proc · %d auth · %d svc · %d listen · %d mod",
			report.Activated, report.Processes, report.Authority, len(report.Services), len(report.Sockets), modules), full: true},
	)
	body := factGrid(facts, width-2)
	// The counts line carries paint per chip, which factGrid's rune-based
	// truncation would corrupt, so it joins the grid after it is laid out.
	body = append(body, findingsFact(report.Findings, factLabelWidth(facts), options.Color))
	fmt.Fprintln(w, rail(head, body, width, mutedColor, options.Color))
	fmt.Fprintln(w)
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
	cell := fmt.Sprintf("%s · %d pkgs · %s hash entries · %d verified",
		summary.Kind, summary.Packages, compactCount(summary.Entries), summary.Verified)
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

// factGrid lays two facts to a row while the line has room, one otherwise;
// the label column is the longest label.
func factGrid(facts []fact, width int) []string {
	labelWidth := factLabelWidth(facts)
	column := (width - labelWidth - 4) / 2
	if column < 16 {
		column = 0
	}
	var lines []string
	for index := 0; index < len(facts); index++ {
		left := fmt.Sprintf("%-*s  %s", labelWidth, facts[index].label, truncate(facts[index].value, width-labelWidth-2))
		if facts[index].full || column == 0 || index+1 >= len(facts) || facts[index+1].full {
			lines = append(lines, left)
			continue
		}
		right := fmt.Sprintf("%-*s  %s", labelWidth, facts[index+1].label,
			truncate(facts[index+1].value, width-labelWidth-2-column-2))
		lines = append(lines, fmt.Sprintf("%-*s  %s", width-column-2, left, right))
		index++
	}
	return lines
}

func factLabelWidth(facts []fact) int {
	labelWidth := 0
	for _, f := range facts {
		if n := utf8.RuneCountInString(f.label); n > labelWidth {
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
func findingsFact(findings []Finding, labelWidth int, color bool) string {
	line := fmt.Sprintf("%-*s  ", labelWidth, "findings")
	if len(findings) == 0 {
		return line + "none"
	}
	counts := make(map[Severity]int, len(findings))
	for _, finding := range findings {
		counts[finding.Severity]++
	}
	chips := make([]string, 0, len(severityNames))
	for _, severity := range []Severity{Critical, High, Medium, Low, Info} {
		if counts[severity] == 0 {
			continue
		}
		text := fmt.Sprintf(" %d %s ", counts[severity], severity)
		chips = append(chips, paintText(color,
			bg(severityColor(severity))+fg(badgeText(severity))+"\x1b[1m", text))
	}
	return line + fmt.Sprintf("%d · ", len(findings)) + strings.Join(chips, " · ")
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

// findingPanel draws one group: the head names the object and its severity,
// the body states the verdict, the relation and the facts behind it.
func findingPanel(group findingGroup, next bool, options RenderOptions, width int) string {
	finding := group[0]
	head := findingHead(finding, width-2, options.Color)
	var body []string
	seen := make(map[string]bool, len(group))
	add := func(line string) {
		if line == "" || seen[line] {
			return
		}
		seen[line] = true
		body = append(body, chrome.WrapProse(line, width-4, 2)...)
	}
	add(paintText(options.Color, "\x1b[1m", finding.Title))
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
		add(line)
	}
	if next && finding.Path != "" {
		add(paintText(options.Color, fg(mutedColor), "· next  ") + "karma graph path:" + finding.Path)
	}
	return rail(head, body, width, severityColor(finding.Severity), options.Color)
}

// quoteRows renders a group's source lines as citation blocks: consecutive
// quotes of one path share a header, and the line numbers hang under it.
func quoteRows(group findingGroup, color bool) []string {
	var quotes []Quote
	seen := make(map[Quote]bool, len(group))
	for _, member := range group {
		for _, quote := range member.Quotes {
			if quote.Path == "" || quote.Text == "" || seen[quote] {
				continue
			}
			seen[quote] = true
			quotes = append(quotes, quote)
		}
	}
	var rows []string
	for index := 0; index < len(quotes); {
		quote := quotes[index]
		head := paintText(color, fg(mutedColor), "· cite  ") + highlightTokens(quote.Path, 0, color)
		if quote.Line == 0 {
			rows = append(rows, head+"  "+highlightTokens(quote.Text, 0, color))
			index++
			continue
		}
		end := index + 1
		for end < len(quotes) && quotes[end].Path == quote.Path && quotes[end].Line != 0 {
			end++
		}
		rows = append(rows, head)
		width := 0
		for _, row := range quotes[index:end] {
			width = max(width, len(strconv.Itoa(row.Line)))
		}
		indent := strings.Repeat(" ", utf8.RuneCountInString("· cite  "))
		for _, row := range quotes[index:end] {
			number := paintText(color, fg(mutedColor), fmt.Sprintf("%*d", width, row.Line))
			rows = append(rows, indent+number+
				paintText(color, fg(mutedColor), " │ ")+highlightTokens(row.Text, 0, color))
		}
		index = end
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
		indent := strings.Repeat(" ", utf8.RuneCountInString("· chain  "))
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
	path := " " + finding.Path
	if utf8.RuneCountInString(label+path) > width {
		path = " " + truncate(finding.Path, width-utf8.RuneCountInString(label)-1)
	}
	plain := label + path
	fill := width - utf8.RuneCountInString(plain)
	if fill < 0 {
		fill = 0
	}
	if !color {
		return strings.TrimRight(plain+strings.Repeat(" ", fill), " ")
	}
	return bg(severityColor(finding.Severity)) + fg(badgeText(finding.Severity)) + "\x1b[1m" +
		label + ansiReset +
		bg(subBandBG) + fg(subBandFG) + path + strings.Repeat(" ", fill) + ansiReset
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

// panel is one evidence section: a title, its rows, and the count the head
// band prints.
type panel struct {
	title string
	rows  []string
	count func(int) int
}

// activationCount counts activation edges; the panel prints two rows per
// edge, the trigger line and the run line.
func activationCount(rows int) int {
	if rows > 1 {
		return (rows - 1) / 2
	}
	return rows
}

// headerless counts rows after the column header.
func headerless(rows int) int {
	if rows > 1 {
		return rows - 1
	}
	return rows
}

// viewPanels builds the evidence sections of one view, in print order. The
// rows come from the view's filtered inventories; the origins come from the
// view's assessor, the same one the findings used.
func viewPanels(view *View, options RenderOptions) []panel {
	return []panel{
		{title: "ACTIVATION", rows: activationRows(view, options), count: activationCount},
		{title: "PROCESS", rows: processRows(view, options), count: headerless},
		{title: "SERVICE", rows: serviceRows(view, options), count: headerless},
		{title: "LISTEN", rows: socketRows(view, options), count: headerless},
		{title: "CONNECTION", rows: connectionRows(view, options), count: headerless},
		{title: "KERNEL", rows: kernelRows(view, options), count: headerless},
		{title: "AUTHORITY", rows: authorityRows(view, options), count: headerless},
		{title: "MOUNTS", rows: mountRows(view, options), count: headerless},
	}
}

func activationRows(view *View, options RenderOptions) []string {
	rows := []string{columnHeader([]string{"SURFACE", "REACH", "AS", "ORIGIN", "TRIGGER"}, []int{10, 12, 10, 10})}
	for _, edge := range view.Activations {
		target := edge.Target
		if edge.Dynamic {
			target = "(dynamic)"
		}
		origin := view.assessor.read(edge.TargetFacts, false).origin
		prefix := columnRowHued(options.Color, []string{
			string(edge.Surface), edge.Phase.String(), valueOr(edge.Subject.String(), "-"), origin.String(),
		}, []int{10, 12, 10, 10}, []int{0, 0, 0, originHue(origin)})
		rows = append(rows, fmt.Sprintf("%s%s:%d", prefix, edge.Trigger, edge.Line))
		rows = append(rows, fmt.Sprintf("    %s -> %s", edge.Mechanism, target))
	}
	if len(rows) == 1 {
		return nil
	}
	return rows
}

func processRows(view *View, options RenderOptions) []string {
	rows := []string{columnHeader([]string{"PID", "PPID", "UID", "ORIGIN", "REACH", "COMMAND"}, []int{7, 7, 6, 10, 8})}
	for _, process := range view.Processes {
		if process.PID == 0 || process.PID == selfPID() {
			continue
		}
		origin := view.assessor.read(process.ExeFacts, false).origin
		if process.Script != "" {
			origin = weaker(origin, view.assessor.read(process.ScriptFacts, false).origin)
		}
		command := process.Cmdline
		if command == "" {
			command = process.Exe
		}
		if process.Script != "" {
			command = process.Script + " (" + command + ")"
		}
		if process.Outbound > 0 {
			command += fmt.Sprintf("  [%d estab]", process.Outbound)
		}
		prefix := columnRowHued(options.Color, []string{
			strconv.Itoa(process.PID), strconv.Itoa(process.PPID), strconv.Itoa(process.UID),
			origin.String(), processReach(process).String(),
		}, []int{7, 7, 6, 10, 8}, []int{0, 0, 0, originHue(origin), 0})
		rows = append(rows, prefix+valueOr(command, valueOr(process.Exe, process.Comm)))
	}
	if len(rows) == 1 {
		return nil
	}
	return rows
}

func serviceRows(view *View, options RenderOptions) []string {
	rows := []string{columnHeader([]string{"UNIT", "LOAD", "ACTIVE", "SUB", "DESCRIPTION"}, []int{28, 8, 8, 8})}
	for _, service := range view.Services {
		rows = append(rows, columnRowHued(options.Color, []string{
			service.Unit, service.Load, service.Active, service.Sub,
		}, []int{28, 8, 8, 8}, []int{0, 0, serviceStateHue(service.Active), 0})+service.Description)
	}
	if len(rows) == 1 {
		return nil
	}
	return rows
}

func socketRows(view *View, options RenderOptions) []string {
	rows := []string{columnHeader([]string{"PROTO", "STATE", "LOCAL", "PEER", "PID", "COMM"}, []int{6, 9, 24, 24, 7})}
	for _, socket := range view.Sockets {
		rows = append(rows, columnRowHued(options.Color, []string{
			socket.Proto, socket.State, socket.Local, socket.Peer,
			strconv.Itoa(socket.PID), socket.Comm,
		}, []int{6, 9, 24, 24, 7}, []int{0, socketStateHue(socket.State), 0, 0, 0, 0}))
	}
	if len(rows) == 1 {
		return nil
	}
	return rows
}

// connectionRows is the established-connection table: the peer side of the
// listener inventory and the evidence behind an interpreter-socket finding.
// The peer is information in the socket language; a shell's name carries the
// warm hue the interpreter finding states.
func connectionRows(view *View, options RenderOptions) []string {
	if len(view.Connections) == 0 {
		return nil
	}
	processes := make(map[int]Process, len(view.Snapshot.Processes))
	for _, process := range view.Snapshot.Processes {
		processes[process.PID] = process
	}
	rows := []string{columnHeader([]string{"PROTO", "LOCAL", "PEER", "PID", "COMM"}, []int{6, 24, 24, 7, 16})}
	for _, connection := range view.Connections {
		rows = append(rows, columnRowHued(options.Color, []string{
			connection.Proto, connection.Local, connection.Peer,
			strconv.Itoa(connection.PID), connection.Comm,
		}, []int{6, 24, 24, 7, 16},
			[]int{0, 0, hueInformation, 0, connectionHue(connection, processes)}))
	}
	return rows
}

// connectionHue answers the hue of the connection's holder: the warm runtime
// hue when any process holding the socket is a shell or a raw-socket tool.
func connectionHue(connection Connection, processes map[int]Process) int {
	if interpreterHolds(connection.PID, processes) {
		return hueAlert
	}
	for _, pid := range connection.PIDs {
		if interpreterHolds(pid, processes) {
			return hueAlert
		}
	}
	return 0
}

func interpreterHolds(pid int, processes map[int]Process) bool {
	process, ok := processes[pid]
	if !ok {
		return false
	}
	_, interpreter := interpreterClass(process)
	return interpreter
}

// kernelRows is the loaded module inventory: name, use count, state, loader
// flags, the module file's origin, and the file itself. Hidden registries and
// the taint mask follow the table because they are facts about the same state.
func kernelRows(view *View, options RenderOptions) []string {
	state := view.Kernel
	if state == nil || !state.Collected {
		return nil
	}
	rows := []string{columnHeader([]string{"MODULE", "USED", "STATE", "TAINT", "ORIGIN"}, []int{26, 5, 10, 6, 10})}
	for _, module := range state.Modules {
		origin, originCode := "-", 0
		if module.File != "" {
			verdict := view.assessor.read(module.Facts, false)
			origin, originCode = verdict.origin.String(), originHue(verdict.origin)
		}
		file := module.File
		if file == "" && module.FileState != "" {
			file = "(" + module.FileState + ")"
			// An unmapped row says nothing about one module when the whole file
			// database belongs to another kernel.
			if module.FileState == ModuleFileMissing ||
				module.FileState == ModuleFileUnmapped && !state.MappingStale {
				file = paintText(options.Color, fg(hueCaution), file)
			}
		}
		rows = append(rows, columnRowHued(options.Color, []string{
			module.Name, strconv.Itoa(module.Used), valueOr(module.State, "-"), valueOr(module.Taint, "-"), origin,
		}, []int{26, 5, 10, 6, 10},
			[]int{0, 0, moduleStateHue(module.State), taintHue(module.Taint), originCode})+file)
	}
	for _, module := range state.Dormant {
		rows = append(rows, paintText(options.Color, fg(mutedColor), "dormant module "+module.Name)+"  "+module.File)
	}
	if state.Tainted != 0 {
		rows = append(rows, paintText(options.Color, fg(hueCaution),
			fmt.Sprintf("taint %d: %s", state.Tainted, strings.Join(state.TaintNames, ", "))))
	}
	for _, hidden := range state.Hidden {
		rows = append(rows, paintText(options.Color, fg(hueAlert),
			"hidden module "+hidden.Name+" ("+strings.Join(hidden.Views, ", ")+")"))
	}
	for _, pid := range state.HiddenPIDs {
		rows = append(rows, paintText(options.Color, fg(hueAlert), fmt.Sprintf("hidden pid %d", pid)))
	}
	if len(state.LoaderDirs) > 0 {
		rows = append(rows, fmt.Sprintf("loader search path: %d directories", len(state.LoaderDirs)))
	}
	if len(rows) == 1 {
		return nil
	}
	return rows
}

func authorityRows(view *View, options RenderOptions) []string {
	rows := []string{columnHeader([]string{"PATH", "ORIGIN", "REACH", "SETUID", "CAPS"}, []int{44, 10, 8, 7, 5})}
	for _, path := range view.Authority {
		facts := view.Facts(path)
		origin := view.assessor.read(facts, true).origin
		rows = append(rows, columnRowHued(options.Color, []string{
			path, origin.String(), authorityReach(facts).String(),
			strconv.FormatBool(facts.Setuid), strconv.FormatBool(facts.Caps),
		}, []int{44, 10, 8, 7, 5}, []int{0, originHue(origin), 0, 0, 0}))
	}
	if len(rows) == 1 {
		return nil
	}
	return rows
}

// mountRows list the mount table: where evidence lives and which of it dies
// with the boot.
func mountRows(view *View, options RenderOptions) []string {
	if len(view.Mounts) == 0 {
		return nil
	}
	rows := []string{columnHeader([]string{"FSTYPE", "PATH", "OPTS"}, []int{12, 26, 34})}
	for _, mount := range view.Mounts {
		rows = append(rows, columnRowHued(options.Color, []string{mount.FSType, mount.Path, mount.Opts},
			[]int{12, 26, 34}, []int{mountTypeHue(mount.FSType), 0, 0}))
	}
	return rows
}

func severityColor(severity Severity) int {
	switch severity {
	case Critical:
		return 1
	case High:
		return 9
	case Medium:
		return 11
	case Low:
		return 14
	}
	return mutedColor
}

func columnHeader(columns []string, widths []int) string {
	return columnRow(columns, widths)
}

func columnRow(values []string, widths []int) string {
	var out strings.Builder
	for index, value := range values {
		if index >= len(widths) {
			out.WriteString(value)
			break
		}
		width := widths[index]
		out.WriteString(padRight(truncate(value, width), width))
		out.WriteString("  ")
	}
	return out.String()
}

// columnRowHued is columnRow with one hue per cell: the padding is painted
// with the cell, so the columns stay aligned; a zero hue leaves it plain.
func columnRowHued(color bool, values []string, widths []int, hues []int) string {
	var out strings.Builder
	for index, value := range values {
		if index >= len(widths) {
			out.WriteString(value)
			break
		}
		width := widths[index]
		cell := padRight(truncate(value, width), width)
		if index < len(hues) && hues[index] != 0 {
			cell = paintText(color, fg(hues[index]), cell)
		}
		out.WriteString(cell)
		out.WriteString("  ")
	}
	return out.String()
}

// originHue is the row palette's temporal verdict, the same language the
// relation tree marks its nodes with: a runtime object warm red, a modified
// or unknown one amber, provisioned calmer, the artifact's own origins muted.
func originHue(origin Origin) int {
	switch origin {
	case Runtime:
		return hueAlert
	case Modified, Unknown:
		return hueCaution
	case Provisioned:
		return hueProvisioned
	}
	return mutedColor
}

// serviceStateHue: a running service is healthy green, a failed one red, a
// transition amber, an inactive one quiet.
func serviceStateHue(state string) int {
	switch state {
	case "active":
		return hueLive
	case "failed":
		return hueFailed
	case "activating", "deactivating", "reloading":
		return hueTransition
	case "inactive":
		return mutedColor
	}
	return 0
}

// socketStateHue: a listening socket asks for attention (amber), an
// established peer is information (cyan), the rest is quiet.
func socketStateHue(state string) int {
	switch state {
	case "LISTEN":
		return hueTransition
	case "ESTAB", "ESTABLISHED":
		return hueInformation
	}
	return 0
}

// moduleStateHue: a loaded module is live, a load or unload in flight is a
// transition, the rest is quiet.
func moduleStateHue(state string) int {
	switch state {
	case "Live":
		return hueLive
	case "Loading", "Unloading":
		return hueTransition
	}
	return 0
}

// taintHue: a loader flag on one module is a caution; an empty column is
// quiet.
func taintHue(taint string) int {
	if taint == "" || taint == "-" {
		return 0
	}
	return hueCaution
}

// mountTypeHue: a remote filesystem is information (cyan), a memory-backed
// one is amber because its evidence dies with the boot.
func mountTypeHue(fstype string) int {
	switch fstype {
	case "nfs", "nfs4", "cifs", "smb3", "smbfs", "sshfs", "fuse.sshfs", "9p", "afs", "nbd":
		return hueInformation
	case "tmpfs", "ramfs", "devtmpfs":
		return hueTransition
	}
	return 0
}

// highlightTokens paints the object and verdict tokens inside one prose
// line: a path keeps the information hue and an origin word keeps its
// temporal hue, while the sentence around them stays in base. An origin word
// is recognised only where a parenthesized explanation follows it
// ("runtime (created ...)"), the shape the judges write.
func highlightTokens(text string, base int, color bool) string {
	if !color || text == "" {
		return text
	}
	paintBase := func(segment string) string {
		if base == 0 {
			return segment
		}
		return paintText(true, fg(base), segment)
	}
	var out strings.Builder
	for index := 0; index < len(text); {
		if text[index] == ' ' {
			end := index
			for end < len(text) && text[end] == ' ' {
				end++
			}
			out.WriteString(paintBase(text[index:end]))
			index = end
			continue
		}
		end := index
		for end < len(text) && text[end] != ' ' {
			end++
		}
		token := text[index:end]
		core, suffix := trimToken(token)
		origin, known := originByName(core)
		switch {
		case strings.HasPrefix(core, "/") && len(core) > 1:
			out.WriteString(paintText(true, fg(hueInformation), core))
			out.WriteString(paintBase(suffix))
		case known && parenFollows(text, end):
			out.WriteString(paintText(true, fg(originHue(origin)), core))
			out.WriteString(paintBase(suffix))
		default:
			out.WriteString(paintBase(token))
		}
		index = end
	}
	return out.String()
}

// trimToken splits the punctuation a prose token may carry after its core.
func trimToken(token string) (core, suffix string) {
	end := len(token)
	for end > 0 && strings.ContainsRune(",.:;)", rune(token[end-1])) {
		end--
	}
	return token[:end], token[end:]
}

// parenFollows reports whether the next non-space character opens the
// explanation the origin slot carries.
func parenFollows(text string, index int) bool {
	for index < len(text) && text[index] == ' ' {
		index++
	}
	return index < len(text) && text[index] == '('
}

// originByName reads an origin word back to its value.
func originByName(name string) (Origin, bool) {
	for index, candidate := range originNames {
		if candidate == name {
			return Origin(index), true
		}
	}
	return Unknown, false
}

func padRight(text string, width int) string {
	if n := utf8.RuneCountInString(text); n < width {
		return text + strings.Repeat(" ", width-n)
	}
	return text
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func selfPID() int { return os.Getpid() }
