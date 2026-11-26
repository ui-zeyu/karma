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

var (
	band         = chrome.Band
	rail         = chrome.Rail
	paintText    = chrome.Paint
	fg           = chrome.Fg
	bg           = chrome.Bg
	displayWidth = chrome.DisplayWidth
	truncate     = chrome.Truncate
)

// Render writes the audit as the operator's worksheet: masthead, findings, the
// raw inventories behind them, and coverage.
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
	for _, finding := range report.Findings {
		fmt.Fprintln(w, findingPanel(finding, options, width))
		fmt.Fprintln(w)
	}
	if options.Evidence && report.snapshot != nil {
		renderEvidence(w, report, options, width)
	}
	if len(report.Coverage) > 0 {
		fmt.Fprintln(w, evidencePanel("COVERAGE", report.Coverage, len(report.Coverage), options, width))
	}
}

func renderMasthead(w io.Writer, report *Report, options RenderOptions, width int) {
	version := options.Version
	if version == "" {
		version = "dev"
	}
	fmt.Fprintln(w, band(" KARMA", "yuyy ", width, bannerBG, bannerFG, true, options.Color))
	head := band(" "+version, clock(), width-2, subBandBG, subBandFG, false, options.Color)
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
	body = append(body, "severity "+severityLegend(options.Color))
	fmt.Fprintln(w, rail(head, body, width, mutedColor, options.Color))
	fmt.Fprintln(w)
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
	labelWidth := 0
	for _, f := range facts {
		if n := utf8.RuneCountInString(f.label); n > labelWidth {
			labelWidth = n
		}
	}
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

func accountCell(host Host) string {
	switch {
	case host.UID == 0:
		return "root (uid 0)"
	case host.UID > 0:
		return fmt.Sprintf("uid %d", host.UID)
	}
	return ""
}

func severityLegend(color bool) string {
	var chips []string
	for _, severity := range []Severity{Critical, High, Medium, Low} {
		chips = append(chips, paintText(color, fg(severityColor(severity)), "● "+severity.String()))
	}
	return strings.Join(chips, "  ")
}

func findingPanel(finding Finding, options RenderOptions, width int) string {
	head := findingHead(finding, width-2, options.Color)
	body := []string{finding.Title}
	if finding.Detail != "" {
		body = append(body, finding.Detail)
	}
	body = append(body, paintText(options.Color, fg(mutedColor),
		fmt.Sprintf("origin %s · reach %s", finding.Origin, finding.Reach)))
	if chain := traceTexts(finding.Trace); len(chain) > 0 {
		body = append(body, paintText(options.Color, fg(mutedColor),
			"· chain  "+strings.Join(chain, " → ")))
	}
	for _, line := range finding.Evidence {
		body = append(body, paintText(options.Color, fg(mutedColor), "· "+line))
	}
	return rail(head, body, width, severityColor(finding.Severity), options.Color)
}

func findingHead(finding Finding, width int, color bool) string {
	label := strings.ToUpper(finding.Severity.String())
	plainLabel := " " + label
	plainPath := "  " + finding.Path
	plain := plainLabel + plainPath
	if utf8.RuneCountInString(plain) > width {
		plainPath = "  " + truncate(finding.Path, width-utf8.RuneCountInString(plainLabel)-2)
		plain = plainLabel + plainPath
	}
	fill := width - utf8.RuneCountInString(plain)
	if fill < 0 {
		fill = 0
	}
	if !color {
		return strings.TrimRight(plain+strings.Repeat(" ", fill), " ")
	}
	return fmt.Sprintf("%s%s%s\x1b[1m%s%s%s%s%s",
		bg(subBandBG), fg(severityColor(finding.Severity)), plainLabel,
		ansiReset, bg(subBandBG), fg(subBandFG), plainPath+strings.Repeat(" ", fill), ansiReset)
}

// panel is one evidence section: a title, its rows, and the count the head
// band prints. Both the full report and `show` print the same panels.
type panel struct {
	title string
	rows  []string
	count func(int) int
}

func (p panel) head(options RenderOptions, width int) string {
	return evidencePanel(p.title, p.rows, p.count(len(p.rows)), options, width)
}

// reportPanels builds the evidence sections of one report, in print order.
// The rows are read from the report's own inventories; the origins come from
// the same assessor the findings used.
func reportPanels(report *Report, options RenderOptions) []panel {
	a := newAssessor(report.snapshot)
	filter := options.Filter
	return []panel{
		{title: "ACTIVATION", rows: activationRows(report, a, filter, options.Color), count: func(n int) int {
			if n > 1 {
				return (n - 1) / 2
			}
			return n
		}},
		{title: "PROCESS", rows: processRows(report, a, filter, options.Color), count: headerless},
		{title: "SERVICE", rows: serviceRows(report, options.Color), count: headerless},
		{title: "LISTEN", rows: socketRows(report, options.Color), count: headerless},
		{title: "CONNECTION", rows: connectionRows(report), count: headerless},
		{title: "KERNEL", rows: kernelRows(report), count: headerless},
		{title: "AUTHORITY", rows: authorityRows(report, a, filter, options.Color), count: headerless},
		{title: "MOUNTS", rows: mountRows(report, options.Color), count: headerless},
	}
}

// headerless counts rows after the column header.
func headerless(rows int) int {
	if rows > 1 {
		return rows - 1
	}
	return rows
}

func renderEvidence(w io.Writer, report *Report, options RenderOptions, width int) {
	fmt.Fprintln(w, band(" EVIDENCE", "", width, bannerBG, bannerFG, true, options.Color))
	for _, section := range reportPanels(report, options) {
		if len(section.rows) > 0 {
			fmt.Fprintln(w, section.head(options, width))
		}
	}
}

func evidencePanel(title string, rows []string, count int, options RenderOptions, width int) string {
	meta := strconv.Itoa(count) + " "
	shown := rows
	if len(shown) > 200 {
		shown = shown[:200]
	}
	body := append([]string(nil), shown...)
	if len(rows) > len(shown) {
		body = append(body, paintText(options.Color, fg(mutedColor),
			fmt.Sprintf("... %d more; narrow the scope or use show", len(rows)-len(shown))))
	}
	head := band(" "+title, meta, width-2, subBandBG, subBandFG, false, options.Color)
	return rail(head, body, width, mutedColor, options.Color)
}

func activationRows(report *Report, a *assessor, filter Filter, color bool) []string {
	if len(filter.PIDs) > 0 {
		return nil
	}
	rows := []string{columnHeader([]string{"SURFACE", "REACH", "AS", "ORIGIN", "TRIGGER"}, []int{10, 12, 10, 10})}
	for _, edge := range report.Activations {
		if !surfaceInScope(edge.Surface, filter) || !pathInScope(edge.Trigger, filter) && !pathInScope(edge.Target, filter) {
			continue
		}
		target := edge.Target
		if edge.Dynamic {
			target = "(dynamic)"
		}
		origin := a.read(edge.TargetFacts, false).origin
		prefix := columnRowHued(color, []string{
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

func processRows(report *Report, a *assessor, filter Filter, color bool) []string {
	rows := []string{columnHeader([]string{"PID", "PPID", "UID", "ORIGIN", "REACH", "COMMAND"}, []int{7, 7, 6, 10, 8})}
	for _, process := range report.ProcessRows {
		if process.PID == 0 || process.PID == selfPID() || !processInScope(process, filter) {
			continue
		}
		origin := a.read(process.ExeFacts, false).origin
		if process.Script != "" {
			origin = weaker(origin, a.read(process.ScriptFacts, false).origin)
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
		prefix := columnRowHued(color, []string{
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

func serviceRows(report *Report, color bool) []string {
	rows := []string{columnHeader([]string{"UNIT", "LOAD", "ACTIVE", "SUB", "DESCRIPTION"}, []int{28, 8, 8, 8})}
	for _, service := range report.Services {
		rows = append(rows, columnRowHued(color, []string{
			service.Unit, service.Load, service.Active, service.Sub,
		}, []int{28, 8, 8, 8}, []int{0, 0, serviceStateHue(service.Active), 0})+service.Description)
	}
	if len(rows) == 1 {
		return nil
	}
	return rows
}

func socketRows(report *Report, color bool) []string {
	rows := []string{columnHeader([]string{"PROTO", "STATE", "LOCAL", "PEER", "PID", "COMM"}, []int{6, 9, 24, 24, 7})}
	for _, socket := range report.Sockets {
		rows = append(rows, columnRowHued(color, []string{
			socket.Proto, socket.State, socket.Local, socket.Peer,
			strconv.Itoa(socket.PID), socket.Comm,
		}, []int{6, 9, 24, 24, 7}, []int{0, socketStateHue(socket.State), 0, 0, 0, 0}))
	}
	if len(rows) == 1 {
		return nil
	}
	return rows
}

// kernelRows is the loaded module inventory: name, use count, state, loader
// flags and the file the module database maps it to. Hidden registries and
// the taint mask follow the table because they are facts about the same state.
func kernelRows(report *Report) []string {
	if report.Kernel == nil {
		return nil
	}
	state := report.Kernel
	if !state.Collected {
		return nil
	}
	rows := []string{columnHeader([]string{"MODULE", "USED", "STATE", "TAINT"}, []int{26, 5, 10, 6})}
	for _, module := range state.Modules {
		file := module.File
		if file == "" && module.FileState != "" {
			file = "(" + module.FileState + ")"
		}
		rows = append(rows, columnRow([]string{
			module.Name, strconv.Itoa(module.Used), valueOr(module.State, "-"), valueOr(module.Taint, "-"),
		}, []int{26, 5, 10, 6})+file)
	}
	for _, module := range state.Dormant {
		rows = append(rows, "dormant module "+module.Name+"  "+module.File)
	}
	if state.Tainted != 0 {
		rows = append(rows, fmt.Sprintf("taint %d: %s", state.Tainted, strings.Join(state.TaintNames, ", ")))
	}
	for _, hidden := range state.Hidden {
		rows = append(rows, "hidden module "+hidden.Name+" ("+strings.Join(hidden.Views, ", ")+")")
	}
	for _, pid := range state.HiddenPIDs {
		rows = append(rows, fmt.Sprintf("hidden pid %d", pid))
	}
	if len(state.LoaderDirs) > 0 {
		rows = append(rows, fmt.Sprintf("loader search path: %d directories", len(state.LoaderDirs)))
	}
	if len(rows) == 1 {
		return nil
	}
	return rows
}

// connectionRows is the established-connection table: the peer side of the
// listener inventory and the evidence behind an interpreter-socket finding.
func connectionRows(report *Report) []string {
	if len(report.Connections) == 0 {
		return nil
	}
	rows := []string{columnHeader([]string{"PROTO", "LOCAL", "PEER", "PID", "COMM"}, []int{6, 24, 24, 7})}
	for _, connection := range report.Connections {
		rows = append(rows, columnRow([]string{
			connection.Proto, connection.Local, connection.Peer,
			strconv.Itoa(connection.PID), connection.Comm,
		}, []int{6, 24, 24, 7}))
	}
	return rows
}

func authorityRows(report *Report, a *assessor, filter Filter, color bool) []string {
	if filter.Surfaces != nil && !filter.Surfaces["authority"] {
		return nil
	}
	rows := []string{columnHeader([]string{"PATH", "ORIGIN", "REACH", "SETUID", "CAPS"}, []int{44, 10, 8, 7, 5})}
	for _, path := range report.AuthorityObjects {
		if !pathInScope(path, filter) {
			continue
		}
		facts := report.snapshot.Facts(path)
		origin := a.read(facts, true).origin
		rows = append(rows, columnRowHued(color, []string{
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
func mountRows(report *Report, color bool) []string {
	if len(report.Mounts) == 0 {
		return nil
	}
	rows := []string{columnHeader([]string{"FSTYPE", "PATH", "OPTS"}, []int{12, 26, 34})}
	for _, mount := range report.Mounts {
		rows = append(rows, columnRowHued(color, []string{mount.FSType, mount.Path, mount.Opts},
			[]int{12, 26, 34}, []int{mountTypeHue(mount.FSType), 0, 0}))
	}
	return rows
}

// showSection is one `show` word and the panel title it prints. The words are
// the same vocabulary the audit's scope grammar already accepts.
var showSection = map[string]string{
	"activation": "ACTIVATION", "persistence": "ACTIVATION", "boot": "ACTIVATION",
	"login": "ACTIVATION", "service": "ACTIVATION", "device": "ACTIVATION",
	"schedule": "ACTIVATION",
	"process":  "PROCESS", "activity": "PROCESS",
	"services":  "SERVICE",
	"listeners": "LISTEN", "sockets": "LISTEN", "listen": "LISTEN",
	"connections": "CONNECTION", "connection": "CONNECTION", "network": "CONNECTION",
	"kernel":    "KERNEL",
	"authority": "AUTHORITY",
	"mounts":    "MOUNTS",
}

// showRows answers one show section's rows and its count function, so the
// text renderer and the JSON encoder print the same answer.
func showRows(snapshot *Snapshot, section string, options RenderOptions) ([]string, func(int) int) {
	if section == "coverage" {
		return Judge(snapshot, options.Filter).Coverage, func(rows int) int { return rows }
	}
	title, ok := showSection[section]
	if !ok {
		return []string{"nothing collected for this section"}, headerless
	}
	report := &Report{
		Services:         snapshot.Services,
		Sockets:          snapshot.Sockets,
		Connections:      snapshot.Connections,
		Mounts:           snapshot.Mounts,
		Activations:      snapshot.Activations,
		ProcessRows:      snapshot.Processes,
		AuthorityObjects: snapshot.Authority,
		snapshot:         snapshot,
	}
	if len(options.Filter.Units) > 0 {
		var services []Service
		for _, service := range snapshot.Services {
			if options.Filter.Units[service.Unit] {
				services = append(services, service)
			}
		}
		report.Services = services
	}
	if section == "kernel" {
		kernel := snapshot.Kernel
		report.Kernel = &kernel
	}
	for _, found := range reportPanels(report, options) {
		if found.title == title {
			return found.rows, found.count
		}
	}
	return []string{"nothing collected for this section"}, headerless
}

// RenderShow prints one raw inventory in the same panel language the report
// prints. It builds the same document the audit renders, then shows one panel.
func RenderShow(w io.Writer, snapshot *Snapshot, section string, options RenderOptions) {
	width := reportWidth(options.Width)
	fmt.Fprintln(w, band(" karma show "+section, "yuyy ", width, bannerBG, bannerFG, true, options.Color))
	rows, count := showRows(snapshot, section, options)
	if len(rows) == 0 {
		rows = []string{"nothing collected for this section"}
	}
	fmt.Fprintln(w, evidencePanel(strings.ToUpper(section), rows, count(len(rows)), options, width))
}

// WriteShowJSON writes one show section as data. JSON carries text, so the
// rows are built without their terminal hues.
func WriteShowJSON(w io.Writer, snapshot *Snapshot, section string, options RenderOptions) error {
	options.Color = false
	rows, _ := showRows(snapshot, section, options)
	out := struct {
		Section string   `json:"section"`
		Rows    []string `json:"rows"`
	}{Section: section, Rows: rows}
	if out.Rows == nil {
		out.Rows = []string{}
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(out)
}

// WriteJSON writes the report as one object.
func WriteJSON(w io.Writer, report *Report) error {
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
	type reportJSON struct {
		Source      string         `json:"source"`
		Host        Host           `json:"host"`
		Boundary    boundaryJSON   `json:"boundary"`
		Findings    []findingJSON  `json:"findings"`
		Services    []Service      `json:"services,omitempty"`
		Listeners   []Socket       `json:"listeners,omitempty"`
		Connections []Connection   `json:"connections,omitempty"`
		Mounts      []Mount        `json:"mounts,omitempty"`
		Ledger      *LedgerSummary `json:"ledger,omitempty"`
		Kernel      *KernelState   `json:"kernel,omitempty"`
		Coverage    []string       `json:"coverage,omitempty"`
	}
	out := reportJSON{
		Source: report.Source,
		Host:   report.Host,
		Boundary: boundaryJSON{
			Kind: report.Boundary.Kind, Source: report.Boundary.Source,
			Confidence: report.Boundary.Confidence.String(),
		},
		Findings:    make([]findingJSON, 0, len(report.Findings)),
		Services:    report.Services,
		Listeners:   report.Sockets,
		Connections: report.Connections,
		Mounts:      report.Mounts,
		Kernel:      report.Kernel,
		Coverage:    report.Coverage,
	}
	if report.Ledger.Kind != "" && report.Ledger.Kind != "none" {
		ledger := report.Ledger
		out.Ledger = &ledger
	}
	if !report.Boundary.Time.IsZero() {
		out.Boundary.Time = report.Boundary.Time.Format(time.RFC3339)
	}
	for _, finding := range report.Findings {
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
		return 203
	case Modified, Unknown:
		return 214
	case Provisioned:
		return 110
	}
	return mutedColor
}

// serviceStateHue: a running service is healthy green, a failed one red, a
// transition amber, an inactive one quiet.
func serviceStateHue(state string) int {
	switch state {
	case "active":
		return 2
	case "failed":
		return 1
	case "activating", "deactivating", "reloading":
		return 3
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
		return 3
	case "ESTAB", "ESTABLISHED":
		return 6
	}
	return 0
}

// mountTypeHue: a remote filesystem is information (cyan), a memory-backed
// one is amber because its evidence dies with the boot.
func mountTypeHue(fstype string) int {
	switch fstype {
	case "nfs", "nfs4", "cifs", "smb3", "smbfs", "sshfs", "fuse.sshfs", "9p", "afs", "nbd":
		return 6
	case "tmpfs", "ramfs", "devtmpfs":
		return 3
	}
	return 0
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
