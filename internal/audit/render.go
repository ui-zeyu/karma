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
	for _, finding := range report.Findings {
		fmt.Fprintln(w, findingPanel(finding, options, width))
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
	body = append(body, "severity "+severityLegend(options.Color))
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
