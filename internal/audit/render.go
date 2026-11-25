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
)

// RenderOptions carries what the report needs to read well on this stream.
type RenderOptions struct {
	Channel  string
	Version  string
	Color    bool
	Evidence bool
	Width    int
	Filter   Filter
}

// The report's chrome, the palette the old surface used: a dark level-one
// band, a lighter level-two band, muted grey, and the severity hues.
const (
	bannerBG   = 236
	bannerFG   = 15
	subBandBG  = 238
	subBandFG  = 250
	mutedColor = 244
	ansiReset  = "\x1b[0m"
)

// Render writes the audit as the operator's worksheet: masthead, findings, the
// raw inventories behind them, and coverage.
func Render(w io.Writer, report *Report, snapshot *Snapshot, options RenderOptions) {
	width := reportWidth(options.Width)
	renderMasthead(w, report, options, width)
	if len(report.Findings) == 0 {
		body := "no findings: the artifact delta is empty and no activation path is writable"
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
	if options.Evidence && snapshot != nil {
		renderEvidence(w, report, snapshot, options, width)
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
	facts := []fact{
		{label: "host", value: valueOr(report.Host.Hostname, "unknown")},
		{label: "channel", value: valueOr(options.Channel, "local")},
		{label: "distro", value: valueOr(report.Host.OS, "unknown distro")},
		{label: "account", value: accountCell(report.Host)},
		{label: "kernel", value: valueOr(report.Host.Kernel, "unknown")},
		{label: "source", value: valueOr(report.Source, "unknown")},
		{label: "ledger", value: ledgerCell(report.Ledger)},
		{label: "boundary", value: boundaryText(report.Boundary), full: true},
		{label: "judged", value: fmt.Sprintf("%d edges · %d proc · %d auth · %d svc · %d listen",
			report.Activated, report.Processes, report.Authority, len(report.Services), len(report.Sockets)), full: true},
	}
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

func renderEvidence(w io.Writer, report *Report, snapshot *Snapshot, options RenderOptions, width int) {
	fmt.Fprintln(w, band(" EVIDENCE", "", width, bannerBG, bannerFG, true, options.Color))
	a := newAssessor(snapshot)
	if rows := activationRows(snapshot, a, options.Filter); len(rows) > 0 {
		fmt.Fprintln(w, evidencePanel("ACTIVATION", rows, (len(rows)-1)/2, options, width))
	}
	if rows := processRows(snapshot, a, options.Filter); len(rows) > 0 {
		fmt.Fprintln(w, evidencePanel("PROCESS", rows, len(rows)-1, options, width))
	}
	if rows := serviceRows(snapshot); len(rows) > 0 {
		fmt.Fprintln(w, evidencePanel("SERVICE", rows, len(rows)-1, options, width))
	}
	if rows := socketRows(snapshot); len(rows) > 0 {
		fmt.Fprintln(w, evidencePanel("LISTEN", rows, len(rows)-1, options, width))
	}
	if rows := authorityRows(snapshot, a, options.Filter); len(rows) > 0 {
		fmt.Fprintln(w, evidencePanel("AUTHORITY", rows, len(rows)-1, options, width))
	}
	if rows := mountRows(snapshot); len(rows) > 0 {
		fmt.Fprintln(w, evidencePanel("MOUNTS", rows, len(rows)-1, options, width))
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

func activationRows(snapshot *Snapshot, a *assessor, filter Filter) []string {
	if len(filter.PIDs) > 0 {
		return nil
	}
	rows := []string{columnHeader([]string{"SURFACE", "REACH", "AS", "ORIGIN", "TRIGGER"}, []int{10, 12, 10, 10})}
	for _, edge := range snapshot.Activations {
		if !surfaceInScope(edge.Surface, filter) || !pathInScope(edge.Trigger, filter) && !pathInScope(edge.Target, filter) {
			continue
		}
		target := edge.Target
		if edge.Dynamic {
			target = "(dynamic)"
		}
		origin := a.read(edge.TargetFacts, false).origin
		prefix := columnRow([]string{
			string(edge.Surface), string(edge.Reach), valueOr(edge.AS, "-"), origin.String(),
		}, []int{10, 12, 10, 10})
		rows = append(rows, fmt.Sprintf("%s%s:%d", prefix, edge.Trigger, edge.Line))
		rows = append(rows, fmt.Sprintf("    %s -> %s", edge.Mechanism, target))
	}
	if len(rows) == 1 {
		return nil
	}
	return rows
}

func processRows(snapshot *Snapshot, a *assessor, filter Filter) []string {
	rows := []string{columnHeader([]string{"PID", "PPID", "UID", "ORIGIN", "REACH", "COMMAND"}, []int{7, 7, 6, 10, 8})}
	for _, process := range snapshot.Processes {
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
		prefix := columnRow([]string{
			strconv.Itoa(process.PID), strconv.Itoa(process.PPID), strconv.Itoa(process.UID),
			origin.String(), processReach(process).String(),
		}, []int{7, 7, 6, 10, 8})
		rows = append(rows, prefix+valueOr(command, valueOr(process.Exe, process.Comm)))
	}
	if len(rows) == 1 {
		return nil
	}
	return rows
}

func serviceRows(snapshot *Snapshot) []string {
	rows := []string{columnHeader([]string{"UNIT", "LOAD", "ACTIVE", "SUB", "DESCRIPTION"}, []int{28, 8, 8, 8})}
	for _, service := range snapshot.Services {
		rows = append(rows, columnRow([]string{
			service.Unit, service.Load, service.Active, service.Sub,
		}, []int{28, 8, 8, 8})+service.Description)
	}
	if len(rows) == 1 {
		return nil
	}
	return rows
}

func socketRows(snapshot *Snapshot) []string {
	rows := []string{columnHeader([]string{"PROTO", "STATE", "LOCAL", "PEER", "PID", "COMM"}, []int{6, 9, 24, 24, 7})}
	for _, socket := range snapshot.Sockets {
		rows = append(rows, columnRow([]string{
			socket.Proto, socket.State, socket.Local, socket.Peer,
			strconv.Itoa(socket.PID), socket.Comm,
		}, []int{6, 9, 24, 24, 7}))
	}
	if len(rows) == 1 {
		return nil
	}
	return rows
}

func authorityRows(snapshot *Snapshot, a *assessor, filter Filter) []string {
	if filter.Surfaces != nil && !filter.Surfaces["authority"] {
		return nil
	}
	rows := []string{columnHeader([]string{"PATH", "ORIGIN", "REACH", "SETUID", "CAPS"}, []int{44, 10, 8, 7, 5})}
	for _, path := range snapshot.Authority {
		if !pathInScope(path, filter) {
			continue
		}
		facts := snapshot.Facts(path)
		origin := a.read(facts, true).origin
		rows = append(rows, columnRow([]string{
			path, origin.String(), authorityReach(facts).String(),
			strconv.FormatBool(facts.Setuid), strconv.FormatBool(facts.Caps),
		}, []int{44, 10, 8, 7, 5}))
	}
	if len(rows) == 1 {
		return nil
	}
	return rows
}

// mountRows list the mount table: where evidence lives and which of it dies
// with the boot.
func mountRows(snapshot *Snapshot) []string {
	if len(snapshot.Mounts) == 0 {
		return nil
	}
	rows := []string{columnHeader([]string{"FSTYPE", "PATH", "OPTS"}, []int{12, 26, 34})}
	for _, mount := range snapshot.Mounts {
		rows = append(rows, columnRow([]string{mount.FSType, mount.Path, mount.Opts}, []int{12, 26, 34}))
	}
	return rows
}

// RenderShow prints one raw inventory in the same panel language.
func RenderShow(w io.Writer, snapshot *Snapshot, section string, options RenderOptions) {
	width := reportWidth(options.Width)
	fmt.Fprintln(w, band(" karma show "+section, "yuyy ", width, bannerBG, bannerFG, true, options.Color))
	a := newAssessor(snapshot)
	var rows []string
	switch section {
	case "activation", "persistence", "boot", "login", "service", "device", "schedule":
		rows = activationRows(snapshot, a, options.Filter)
	case "process", "activity":
		rows = processRows(snapshot, a, options.Filter)
	case "services":
		rows = serviceRows(snapshot)
	case "listeners", "sockets", "listen":
		rows = socketRows(snapshot)
	case "authority":
		rows = authorityRows(snapshot, a, options.Filter)
	case "mounts":
		rows = mountRows(snapshot)
	case "coverage":
		rows = append(rows, Judge(snapshot, options.Filter).Coverage...)
	}
	if len(rows) == 0 {
		rows = []string{"nothing collected for this section"}
	}
	count := len(rows)
	switch section {
	case "activation", "persistence", "boot", "login", "service", "device", "schedule":
		if len(rows) > 1 {
			count = (len(rows) - 1) / 2
		}
	case "process", "activity", "services", "authority", "listeners", "sockets", "listen", "mounts":
		if len(rows) > 1 {
			count = len(rows) - 1
		}
	}
	fmt.Fprintln(w, evidencePanel(strings.ToUpper(section), rows, count, options, width))
}

// WriteJSON writes the report as one object.
func WriteJSON(w io.Writer, report *Report, channel string) error {
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
		Evidence []string `json:"evidence,omitempty"`
	}
	type reportJSON struct {
		Channel   string         `json:"channel,omitempty"`
		Source    string         `json:"source"`
		Host      Host           `json:"host"`
		Boundary  boundaryJSON   `json:"boundary"`
		Findings  []findingJSON  `json:"findings"`
		Services  []Service      `json:"services,omitempty"`
		Listeners []Socket       `json:"listeners,omitempty"`
		Mounts    []Mount        `json:"mounts,omitempty"`
		Ledger    *LedgerSummary `json:"ledger,omitempty"`
		Coverage  []string       `json:"coverage,omitempty"`
	}
	out := reportJSON{
		Channel: channel,
		Source:  report.Source,
		Host:    report.Host,
		Boundary: boundaryJSON{
			Kind: report.Boundary.Kind, Source: report.Boundary.Source,
			Confidence: report.Boundary.Confidence.String(),
		},
		Findings:  make([]findingJSON, 0, len(report.Findings)),
		Services:  report.Services,
		Listeners: report.Sockets,
		Mounts:    report.Mounts,
		Coverage:  report.Coverage,
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
			Detail: finding.Detail, Evidence: finding.Evidence,
		})
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(out)
}

// rail draws one panel: a half-block rail in the severity color, a filled head
// band, and body rows indented two columns.
func rail(head string, body []string, width, railColor int, color bool) string {
	inner := width - 2
	lines := []string{head}
	for _, line := range body {
		line = strings.TrimRight(line, " ")
		for _, wrapped := range wrapText(line, inner-2) {
			lines = append(lines, "  "+wrapped)
		}
	}
	prefix := paintText(color, fg(railColor), "▌")
	var out strings.Builder
	for _, line := range lines {
		out.WriteString(prefix)
		out.WriteString(line)
		out.WriteString("\n")
	}
	return strings.TrimRight(out.String(), "\n")
}

// band fills one line: the label on the left, the metadata on the right.
func band(left, right string, width, bgCode, fgCode int, bold, color bool) string {
	if width < 8 {
		width = 8
	}
	if utf8.RuneCountInString(left)+utf8.RuneCountInString(right) > width {
		right = ""
		left = truncate(left, width)
	}
	fill := width - utf8.RuneCountInString(left) - utf8.RuneCountInString(right)
	if fill < 0 {
		fill = 0
	}
	plain := left + strings.Repeat(" ", fill) + right
	if !color {
		return strings.TrimRight(plain, " ")
	}
	style := bg(bgCode) + fg(fgCode)
	if bold {
		style += "\x1b[1m"
	}
	return style + plain + ansiReset
}

func fg(code int) string { return fmt.Sprintf("\x1b[38;5;%dm", code) }
func bg(code int) string { return fmt.Sprintf("\x1b[48;5;%dm", code) }

func paintText(color bool, codes, text string) string {
	if !color || codes == "" {
		return text
	}
	return codes + text + ansiReset
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

func padRight(text string, width int) string {
	if n := utf8.RuneCountInString(text); n < width {
		return text + strings.Repeat(" ", width-n)
	}
	return text
}

func truncate(text string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(text)
	if len(runes) <= width {
		return text
	}
	if width == 1 {
		return "…"
	}
	return string(runes[:width-1]) + "…"
}

// wrapText breaks a body line inside the panel: between words first, then at a
// slash, and by character only when one token is wider than the line.
func wrapText(text string, width int) []string {
	if width < 8 {
		width = 8
	}
	if displayWidth(text) <= width {
		return []string{text}
	}
	text = stripANSI(text)
	if strings.Contains(text, "  ") {
		var out []string
		runes := []rune(text)
		for len(runes) > width {
			out = append(out, string(runes[:width]))
			runes = runes[width:]
		}
		return append(out, string(runes))
	}
	var lines []string
	for _, word := range strings.Fields(text) {
		if len(lines) == 0 {
			lines = append(lines, word)
			continue
		}
		if utf8.RuneCountInString(lines[len(lines)-1])+1+utf8.RuneCountInString(word) <= width {
			lines[len(lines)-1] += " " + word
			continue
		}
		lines = append(lines, word)
	}
	var out []string
	for _, line := range lines {
		for utf8.RuneCountInString(line) > width {
			runes := []rune(line)
			out = append(out, string(runes[:width]))
			line = string(runes[width:])
		}
		out = append(out, line)
	}
	return out
}

// displayWidth is a string's printed width: ANSI escapes take no column.
func displayWidth(text string) int {
	width := 0
	for index := 0; index < len(text); {
		if text[index] == 0x1b {
			for index < len(text) && text[index] != 'm' {
				index++
			}
			index++
			continue
		}
		_, size := utf8.DecodeRuneInString(text[index:])
		index += size
		width++
	}
	return width
}

// stripANSI drops SGR sequences: a line that has to wrap loses its paint rather
// than letting a wrap land inside an escape.
func stripANSI(text string) string {
	var out strings.Builder
	for index := 0; index < len(text); {
		if text[index] == 0x1b {
			for index < len(text) && text[index] != 'm' {
				index++
			}
			index++
			continue
		}
		out.WriteByte(text[index])
		index++
	}
	return out.String()
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func selfPID() int { return os.Getpid() }
