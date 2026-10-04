// Presentation palette and inline coloring: the severity color language, the
// legend source, the lexers, and the built-in pseudo-lexers.
//
// render only does layout (boxes, progress, budget); coloring of text coming
// from the target all comes from here. Every hit span and the legend share the
// same severity colors; syntax coloring stays low-saturation to keep clear of
// the red/yellow/cyan/green severity semantics. Syntax highlighting uses chroma
// (bash), and line-shaped output uses the built-in pseudo-lexers.
package render

import (
	"iter"
	"regexp"
	"slices"
	"strings"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/charmbracelet/lipgloss"
	"github.com/samber/lo"

	"karma/internal/model"
)

// --- regex helpers ---

func compile(expr string) *regexp.Regexp { return regexp.MustCompile(expr) }

// findSubindex returns the byte spans of the named groups; a group that did not
// match is skipped.
func findSubindex(re *regexp.Regexp, line string) map[string][2]int {
	idx := re.FindStringSubmatchIndex(line)
	if idx == nil {
		return nil
	}
	out := map[string][2]int{}
	for i, name := range re.SubexpNames() {
		if name == "" || idx[2*i] < 0 {
			continue
		}
		out[name] = [2]int{idx[2*i], idx[2*i+1]}
	}
	return out
}

// style is the smallest description of one painting; it turns into lipgloss
// SGR output.
type style struct {
	fg     lipgloss.Color
	bg     lipgloss.Color
	bold   bool
	faint  bool
	italic bool
}

func (s style) seq() lipgloss.Style {
	out := lipgloss.NewStyle()
	if s.bold {
		out = out.Bold(true)
	}
	if s.faint {
		out = out.Faint(true)
	}
	if s.italic {
		out = out.Italic(true)
	}
	if s.fg != "" {
		out = out.Foreground(s.fg)
	}
	if s.bg != "" {
		out = out.Background(s.bg)
	}
	return out
}

var (
	// MutedColor is the single source of muting: the muted style, the grey rail
	// of a quiet check and of a skipped block, and the right-hand annotations
	// share the same grey (a darker grey is invisible in the user's light
	// theme).
	MutedColor    = lipgloss.Color("244")
	criticalStyle = style{fg: "15", bg: "1", bold: true} // bold white on red
	highStyle     = style{fg: "9", bold: true}           // bold bright_red
	mediumStyle   = style{fg: "11", bold: true}          // bold bright_yellow
	lowStyle      = style{fg: "14"}                      // bright_cyan
	mutedStyle    = style{fg: MutedColor}                // grey50
	accentStyle   = style{fg: "14"}                      // bright_cyan
	dimStyle      = style{faint: true}

	// Aspect banner: a neutral dark background with white text, keeping clear
	// of the severity colors.
	bannerColor     = lipgloss.Color("236")
	bannerTextColor = lipgloss.Color("15")
)

// severityStyle is shared by hit spans and the legend; it covers the four
// signal severities only — benign and no-hit are both quiet lines.
func severityStyle(severity model.Severity) style {
	switch severity {
	case model.Critical:
		return criticalStyle
	case model.High:
		return highStyle
	case model.Medium:
		return mediumStyle
	case model.Low:
		return lowStyle
	}
	return style{}
}

// severityBorder is the border hue. A critical hit span is white on red, so the
// border takes the red itself.
func severityBorder(severity model.Severity) lipgloss.Color {
	switch severity {
	case model.Critical:
		return "1"
	case model.High:
		return "9"
	case model.Medium:
		return "11"
	case model.Low:
		return "14"
	default:
		return ""
	}
}

// Syntax coloring uses low-saturation dark colors and is applied before hit
// spans (syntax < hits); bright magenta reads like the severity red in a light
// terminal, so keywords use dark magenta.
var (
	commentColor = style{faint: true}
	keywordColor = style{fg: "5"} // magenta
	stringColor  = style{fg: "4"} // blue, same as Number
)

// Span is one painted span (byte offsets).
type Span struct {
	Start int
	End   int
	Style style
}

// LineStyler produces syntax spans for one body line; a lexer that carries
// state across lines (table column anchors) gets one instance per check, built
// by newLineStyler.
type LineStyler func(line string) []Span

// newLineStyler returns the inline coloring function for the declared syntax,
// with insurance: a lexer panic (odd target output hitting a hard-coded line
// shape) permanently degrades this check's syntax coloring to plain text,
// while hit highlighting and body output carry on.
func newLineStyler(syntax string) LineStyler {
	return safeLineStyler(buildLineStyler(syntax))
}

// safeLineStyler wraps a lexer with insurance: an instance that blew up once is
// permanently degraded to plain text (its cross-line state may already be
// polluted, and coloring against a wrong anchor is worse than plain text).
func safeLineStyler(styler LineStyler) LineStyler {
	if styler == nil {
		return nil
	}
	poisoned := false
	return func(line string) (spans []Span) {
		if poisoned {
			return nil
		}
		defer func() {
			if recover() != nil {
				poisoned, spans = true, nil
			}
		}()
		return styler(line)
	}
}

// buildLineStyler is the syntax table. Built-in pseudo-lexers are reused
// directly; bash goes through chroma; an unknown declaration means no
// highlighting.
func buildLineStyler(syntax string) LineStyler {
	switch syntax {
	case "ls-l":
		return styleLsL
	case "env":
		return styleEnv
	case "dmesg":
		return styleDmesg
	case "sshd-config":
		return styleSshdConfig
	case "ssh-pubkey":
		return styleSSHPublicKey
	case "colon":
		return styleColonTable
	case "lsmod":
		return styleLsmod
	case "ip-addr":
		return styleIPAddr
	case "table":
		return newTableStyler(nil, true).style
	case "listen":
		return newTableStyler([]*regexp.Regexp{compile(`^Netid\s+State\s`), compile(`^Proto\s+Recv-Q\s+Send-Q\s`)}, true).style
	case "netstat":
		return newTableStyler([]*regexp.Regexp{compile(`^\s*Proto\s+Local`)}, true).style
	case "ip-keyval":
		return newKeyvalStyler().style
	case "reg":
		return styleReg
	case "pipe":
		return stylePipeTable
	case "powershell":
		return chromaLineStyler(chromaLexers["powershell"])
	case "bash":
		return chromaLineStyler(chromaLexers["bash"])
	}
	return nil
}

// paintLine paints one line by span: spans apply in stacking order, later ones
// covering earlier ones (the syntax layer lands first, hit spans and comment
// muting later). Non-overlapping spans leave the output unchanged, and an empty
// span set returns the text as is.
func paintLine(text string, spans []Span) string {
	if len(spans) == 0 {
		return text
	}
	// Record, per byte, the index of the last span covering it, then merge the
	// output into runs
	winner := make([]int, len(text))
	for i := range winner {
		winner[i] = -1
	}
	for index, span := range spans {
		start, end := max(span.Start, 0), min(span.End, len(text))
		for i := start; i < end; i++ {
			winner[i] = index
		}
	}
	var out strings.Builder
	for pos := 0; pos < len(text); {
		end := pos + 1
		for end < len(text) && winner[end] == winner[pos] {
			end++
		}
		if index := winner[pos]; index >= 0 {
			out.WriteString(spans[index].Style.seq().Render(text[pos:end]))
		} else {
			out.WriteString(text[pos:end])
		}
		pos = end
	}
	return out.String()
}

// --- built-in pseudo-lexers (regex line shapes, byte offsets within the line) ---

var (
	lsTotal = compile(`^total \S+$`)
	// ls -l line shape: perms links owner group size date time path
	lsLine = compile(`^(?P<perms>[-dlbcps][rwxsStT-]{9}[.+]?)\s+\d+\s+\S+\s+\S+\s+` +
		`(?P<size>\S+)\s+(?P<date>[A-Z][a-z]{2}\s+\d{1,2}\s+(?:\d{1,2}:\d{2}(?::\d{2})?|\d{4}))\s+` +
		`(?P<name>.+)$`)
	envName   = compile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	dmesgTS   = compile(`^\[\s*\d+\.\d+\]\s`)
	sshdDirm  = compile(`^[ \t]*[A-Za-z][A-Za-z0-9-]*`)
	sshPubKey = compile(`(?P<type>(?:sk-)?(?:ecdsa-sha2-nistp\d+|ssh-(?:rsa|dss|ed25519))(?:@openssh\.com)?)` +
		`\s+(?P<blob>[A-Za-z0-9+/]{20,}={0,2})`)
	brAddrRow = compile(`^(?P<iface>\S+)\s{2,}(?P<state>\S+)(?:\s{2,}(?P<rest>\S.*))?$`)
	// ip -br addr columns are separated by 2+ spaces and an address cell has
	// spaces inside (several addresses per interface); the state gets a semantic
	// color
	brStateStyles = map[string]style{
		"UP":      {fg: "2"},
		"DOWN":    {faint: true},
		"UNKNOWN": {faint: true},
	}
)

func styleLsL(line string) []Span {
	if lsTotal.MatchString(line) {
		return []Span{{Start: 0, End: len(line), Style: mutedStyle}}
	}
	matched := findSubindex(lsLine, line)
	if matched == nil {
		return nil
	}
	perms := line[matched["perms"][0]:matched["perms"][1]]
	nameAt := matched["name"][0]
	// The metadata is muted as a whole first, then lit up column by column
	spans := []Span{{Start: 0, End: nameAt, Style: mutedStyle}}
	spans = append(spans, permissionSpans(perms)...)
	spans = append(spans, Span{Start: matched["size"][0], End: matched["size"][1], Style: style{fg: "247"}})
	dateStyle := style{fg: "2"} // dark_green: with a time it is a recent change
	if !strings.Contains(line[matched["date"][0]:matched["date"][1]], ":") {
		dateStyle = style{fg: "6"} // year only, cyan
	}
	spans = append(spans, Span{Start: matched["date"][0], End: matched["date"][1], Style: dateStyle})
	if kind := lsKindStyle(perms); kind != nil {
		spans = append(spans, Span{Start: nameAt, End: len(line), Style: *kind})
		if perms[0] == 'l' { // symlink: the arrow is dimmed, name and target share a color
			if arrow := strings.Index(line[nameAt:], " -> "); arrow >= 0 {
				spans = append(spans, Span{Start: nameAt + arrow, End: nameAt + arrow + 4, Style: mutedStyle})
			}
		}
	}
	return spans
}

// permissionSpans paints the permission bits one by one; the first character is
// the type, and missing bits plus a trailing ACL indicator (. +) stay muted.
func permissionSpans(perms string) []Span {
	return lo.FilterMap([]byte(perms), func(flag byte, offset int) (Span, bool) {
		st := lsFlagStyle(flag)
		if offset == 0 {
			st = lsTypeStyle(flag)
		}
		if st == nil {
			return Span{}, false
		}
		return Span{Start: offset, End: offset + 1, Style: *st}, true
	})
}

// Permission bits one by one; missing bits and a trailing ACL indicator (. +)
// stay muted
func lsFlagStyle(flag byte) *style {
	switch flag {
	case 'r':
		return &style{fg: "2"}
	case 'w':
		return &style{fg: "3"}
	case 'x':
		return &style{fg: "1"}
	case 's', 'S', 't', 'T':
		return &style{fg: "5", bold: true}
	}
	return nil
}

// The type character shares the name's color family (not bold); a regular
// file's - stays muted
func lsTypeStyle(flag byte) *style {
	switch flag {
	case 'd':
		return &style{fg: "4"}
	case 'l':
		return &style{fg: "6"}
	case 'b', 'c', 'p', 's':
		return &style{fg: "5"}
	}
	return nil
}

func lsKindStyle(perms string) *style {
	switch {
	case perms[0] == 'd':
		return &style{fg: "4", bold: true}
	case perms[0] == 'l':
		return &style{fg: "6"}
	case strings.ContainsRune("bcps", rune(perms[0])) ||
		strings.ContainsAny(perms, "sS"):
		return &style{fg: "5", bold: true}
	case strings.Contains(perms, "x"):
		return &style{fg: "2", bold: true}
	}
	return nil
}

func styleEnv(line string) []Span {
	if matched := envName.FindStringIndex(line); matched != nil {
		// Paint only the = separating key and value and keep both sides at the
		// default color — painting the whole line reads as an alert
		return []Span{{Start: matched[1] - 1, End: matched[1], Style: style{fg: "5"}}}
	}
	return nil
}

func styleDmesg(line string) []Span {
	if matched := dmesgTS.FindStringIndex(line); matched != nil {
		return []Span{{Start: matched[0], End: matched[1], Style: mutedStyle}}
	}
	return nil
}

func styleSshdConfig(line string) []Span {
	// "directive at line start, then value" form: only the directive name is lit
	// (blue) and the value stays at the default color — a field of bright
	// magenta would read as the severity red
	if matched := sshdDirm.FindStringIndex(line); matched != nil {
		return []Span{{Start: matched[0], End: matched[1], Style: style{fg: "4"}}}
	}
	return nil
}

func styleSSHPublicKey(line string) []Span {
	// "type base64 comment" form (possibly with an options prefix): the key type
	// is lit and the base64 blob is dimmed — that string is unreadable noise;
	// the comment stays at the default color
	matched := sshPubKey.FindStringSubmatchIndex(line)
	if matched == nil {
		return nil
	}
	typeIdx := sshPubKey.SubexpIndex("type") * 2
	blobIdx := sshPubKey.SubexpIndex("blob") * 2
	if typeIdx < 0 || blobIdx < 0 {
		return nil
	}
	return []Span{
		{Start: matched[typeIdx], End: matched[typeIdx+1], Style: style{fg: "4"}},
		{Start: matched[blobIdx], End: matched[blobIdx+1], Style: dimStyle},
	}
}

// The five column colors: base blue first, then the dark family used by ls -l;
// the severity colors are avoided
var tableColumnStyles = [5]style{
	{fg: "4"},
	{fg: "3"},
	{fg: "5"},
	{fg: "2"},
	{fg: "6"},
}

var (
	wsColumn    = compile(`\S+`)
	headerToken = compile(`[%A-Z][A-Z0-9%<>@.+-]*`)
	// The first line of procps `w` is an uptime banner that appears before the
	// USER/TTY header. There is no column anchor yet, and cycling word by word
	// would paint "21:31:02 up 95 days, … load average: …" in five colors. The
	// whole line is muted instead; login rows after the header still get their
	// column colors.
	uptimeBanner = compile(`^\s*\d{1,2}:\d{2}(?::\d{2})?\s+up\b`)
)

// tableStyler colors table columns anchored on the header (it carries the
// column anchors across lines; one instance per check).
type tableStyler struct {
	headers []*regexp.Regexp
	cycle   bool
	starts  []int
}

func newTableStyler(headers []*regexp.Regexp, cycle bool) *tableStyler {
	return &tableStyler{headers: headers, cycle: cycle}
}

func (t *tableStyler) style(line string) []Span {
	if uptimeBanner.MatchString(line) {
		return []Span{{Start: 0, End: len(line), Style: mutedStyle}}
	}
	columns := slices.Collect(matches(wsColumn, line))
	if len(columns) < 2 {
		return nil
	}
	headerAnchored := lo.SomeBy(t.headers, func(header *regexp.Regexp) bool {
		loc := header.FindStringIndex(line)
		return loc != nil && loc[0] == 0
	})
	allCaps := lo.EveryBy(columns, func(column word) bool {
		return wholeToken(headerToken, column.text)
	})
	if headerAnchored || allCaps {
		t.starts = lo.Map(columns, func(column word, _ int) int { return column.start })
		return nil
	}
	if len(t.starts) == 0 {
		if t.cycle {
			return cycleColumns(columns)
		}
		return nil
	}
	// Boundary tolerance: in tables aligned to their widest cell (ss and
	// similar), a data column's left edge can float 1–2 characters left of the
	// header word; a word starting inside a header interval (tolerance
	// included) gets that column's color
	const columnTol = 2
	var spans []Span
	for _, column := range columns {
		pos, _ := slices.BinarySearch(t.starts, column.start+columnTol+1)
		pos = max(pos-1, 0)
		if pos < len(t.starts)-1 {
			spans = append(spans, Span{
				Start: column.start, End: column.end,
				Style: tableColumnStyles[pos%len(tableColumnStyles)],
			})
		}
	}
	return spans
}

// word is one word of a line. Regex match pair indices are unpacked once, in
// matches.
type word struct {
	start int
	end   int
	text  string
}

// matches iterates every match of a regex in one line.
func matches(re *regexp.Regexp, line string) iter.Seq[word] {
	return func(yield func(word) bool) {
		for _, loc := range re.FindAllStringIndex(line, -1) {
			if !yield(word{start: loc[0], end: loc[1], text: line[loc[0]:loc[1]]}) {
				return
			}
		}
	}
}

func wholeToken(re *regexp.Regexp, text string) bool {
	loc := re.FindStringIndex(text)
	return loc != nil && loc[0] == 0 && loc[1] == len(text)
}

// cycleColumns falls back to cycling word by word when there is no header to
// anchor on; the last word keeps the default color.
func cycleColumns(columns []word) []Span {
	return lo.Map(columns[:len(columns)-1], func(column word, index int) Span {
		return Span{
			Start: column.start, End: column.end,
			Style: tableColumnStyles[index%len(tableColumnStyles)],
		}
	})
}

// lsmodHeader is the header row of procps `lsmod`. The /proc/modules fallback
// tier has no header, and its data rows are colored straight by line shape.
var lsmodHeader = compile(`^Module\s+Size\s+Used by\b`)

// styleLsmod colors the kernel module table: module name, size, and reference
// count by column. The Used by tail (which may contain spaces) and the
// dependency and state fields of /proc/modules keep the default color; the
// header row is not painted.
func styleLsmod(line string) []Span {
	if lsmodHeader.MatchString(line) {
		return nil
	}
	columns := slices.Collect(matches(wsColumn, line))
	if len(columns) < 3 {
		return nil
	}
	spans := make([]Span, 0, 3)
	for i := range 3 {
		spans = append(spans, Span{
			Start: columns[i].start, End: columns[i].end,
			Style: tableColumnStyles[i],
		})
	}
	return spans
}

func styleIPAddr(line string) []Span {
	// ip -br addr rows are colored by column: interface blue, state by meaning,
	// the addresses themselves at the default color
	matched := findSubindex(brAddrRow, line)
	if matched == nil {
		return nil
	}
	spans := []Span{{Start: matched["iface"][0], End: matched["iface"][1], Style: style{fg: "4"}}}
	state := line[matched["state"][0]:matched["state"][1]]
	if st, ok := brStateStyles[state]; ok {
		spans = append(spans, Span{Start: matched["state"][0], End: matched["state"][1], Style: st})
	}
	return spans
}

var (
	// Key/value rows of ip route / ip neigh: the destination is lit, keys get
	// dark magenta, and a trailing all-caps word is a neighbor state
	// (REACHABLE/STALE…), which gets cyan
	keyvalKeys = compile(`\b(?:via|dev|proto|scope|src|metric|table|mtu|weight|onlink|lladdr|nud` +
		`|expires|offload)\b`)
	keyvalDest = compile(`^(?:default|blackhole|unreachable|prohibit|throw` +
		`|(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,3})?` +
		`|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})`)
	routeTableHeader = compile(`^Destination\s+Gateway\s`)
	arpTableHeader   = compile(`^Address\s+HWtype\s`)
)

// keyvalStyler colors the key/value rows of ip route / ip neigh; header rows are
// anchored and then given column colors by interval.
type keyvalStyler struct {
	table *tableStyler
}

func newKeyvalStyler() *keyvalStyler {
	// cycle off: preamble lines such as netstat's "Kernel IP routing table" are
	// not table data and stay plain until the anchor is set
	return &keyvalStyler{table: newTableStyler([]*regexp.Regexp{routeTableHeader, arpTableHeader}, false)}
}

func (k *keyvalStyler) style(line string) []Span {
	columns := slices.Collect(matches(wsColumn, line))
	if len(columns) < 2 {
		return nil
	}
	first, last := columns[0], columns[len(columns)-1]
	if keyvalKeys.MatchString(line) && keyvalDest.MatchString(first.text) {
		spans := []Span{{Start: first.start, End: first.end, Style: style{fg: "4"}}}
		for key := range matches(keyvalKeys, line) {
			spans = append(spans, Span{Start: key.start, End: key.end, Style: style{fg: "5"}})
		}
		if wholeToken(headerToken, last.text) {
			spans = append(spans, Span{Start: last.start, End: last.end, Style: style{fg: "6"}})
		}
		return spans
	}
	return k.table.style(line)
}

// styleColonTable cycles colors through the fields of a colon-separated table
// (passwd/group); the last field keeps the default color.
func styleColonTable(line string) []Span {
	fields := strings.Split(line, ":")
	if len(fields) < 2 {
		return nil
	}
	var spans []Span
	offset := 0
	for index, field := range fields[:len(fields)-1] {
		spans = append(spans, Span{
			Start: offset, End: offset + len(field),
			Style: tableColumnStyles[index%len(tableColumnStyles)],
		})
		offset += len(field) + 1
	}
	return spans
}

// chromaLexers is fetched once at package level: Tokenise builds fresh state per
// call, so nothing is shared across calls or goroutines.
var chromaLexers = map[string]chroma.Lexer{
	"bash":       lexers.Get("bash"),
	"powershell": lexers.Get("powershell"),
}

// chromaLineStyler is the chroma lexical surface: Comment dimmed, Keyword dark
// magenta, String and Number blue. Syntax colors stay low-saturation so they do
// not compete with the severity colors.
func chromaLineStyler(lexer chroma.Lexer) LineStyler {
	return func(line string) []Span {
		if lexer == nil {
			return nil
		}
		iterator, err := lexer.Tokenise(nil, line)
		if err != nil {
			return nil
		}
		var spans []Span
		offset := 0
		for _, token := range iterator.Tokens() {
			if st, ok := chromaTokenStyle(token.Type); ok && token.Value != "" {
				spans = append(spans, Span{Start: offset, End: offset + len(token.Value), Style: st})
			}
			offset += len(token.Value)
		}
		return spans
	}
}

func chromaTokenStyle(t chroma.TokenType) (style, bool) {
	switch {
	case t.InCategory(chroma.Comment) || t == chroma.Comment:
		return commentColor, true
	case t.InCategory(chroma.Keyword) || t == chroma.Keyword || t == chroma.NameBuiltin:
		// A cmdlet (Invoke-Expression and friends) is a key verb in a history
		// command, so it shares the keyword color
		return keywordColor, true
	case t.InCategory(chroma.LiteralString) || t.InCategory(chroma.LiteralNumber):
		return stringColor, true
	}
	return style{}, false
}

// --- Windows pseudo-lexers ---

var (
	// reg.exe value rows: 4-space indent, 4+ spaces between columns (the same
	// shape checks/windows/regutil parses)
	regValueRow = compile(`^(?P<indent>\s+)(?P<name>\S.*?)\s{4}(?P<type>REG_[A-Z]+)\s+(?P<data>.*)$`)
	regHexData  = compile(`^(?:0x[0-9A-Fa-f]+\b|[0-9A-Fa-f]{2}(?:,[0-9A-Fa-f]{2})+)`)
	regContin   = compile(`^ {8,}\S`)
)

// styleReg colors a reg query dump: the key path whole-line blue, a value row's
// name blue, its type dark magenta, and hex data dimmed, with other data at the
// default color.
func styleReg(line string) []Span {
	if strings.HasPrefix(line, "HKEY_") {
		return []Span{{Start: 0, End: len(line), Style: style{fg: "4"}}}
	}
	if regContin.MatchString(line) {
		return []Span{{Start: 0, End: len(line), Style: dimStyle}}
	}
	matched := findSubindex(regValueRow, line)
	if matched == nil {
		return nil
	}
	spans := []Span{
		{Start: matched["name"][0], End: matched["name"][1], Style: style{fg: "4"}},
		{Start: matched["type"][0], End: matched["type"][1], Style: keywordColor},
	}
	if regHexData.MatchString(line[matched["data"][0]:matched["data"][1]]) {
		spans = append(spans, Span{Start: matched["data"][0], End: matched["data"][1], Style: dimStyle})
	}
	return spans
}

var (
	pipeLabel = compile(`Installed|Last Connected|Last Removed`)
	pipeTime  = compile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}`)
)

// stylePipeTable handles ` | `-segmented rows (usb-devices' "name | instance |
// label time" and software's "name | version | date"): the first segment blue,
// the second dimmed, known labels muted, times green, and the separators muted.
func stylePipeTable(line string) []Span {
	segments := strings.Split(line, " | ")
	if len(segments) < 2 {
		return nil
	}
	var spans []Span
	offset := 0
	for index, segment := range segments {
		switch index {
		case 0:
			spans = append(spans, Span{Start: offset, End: offset + len(segment), Style: style{fg: "4"}})
		case 1:
			spans = append(spans, Span{Start: offset, End: offset + len(segment), Style: dimStyle})
		default:
			for _, loc := range pipeLabel.FindAllStringIndex(segment, -1) {
				spans = append(spans, Span{Start: offset + loc[0], End: offset + loc[1], Style: mutedStyle})
			}
			for _, loc := range pipeTime.FindAllStringIndex(segment, -1) {
				spans = append(spans, Span{Start: offset + loc[0], End: offset + loc[1], Style: style{fg: "2"}})
			}
		}
		if index < len(segments)-1 {
			sep := offset + len(segment)
			spans = append(spans, Span{Start: sep, End: sep + 3, Style: mutedStyle})
		}
		offset += len(segment) + 3
	}
	return spans
}
