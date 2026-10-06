// table pseudo-lexer: column colors anchored on the header row, shared by the
// generic "table" syntax and the header-specific variants (listen, netstat,
// df).

package render

import (
	"iter"
	"regexp"
	"slices"

	"github.com/samber/lo"
)

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

	// dfHeader anchors df's columns. The capture groups make "Mounted on" one
	// column instead of two words; the middle groups take the variants (GNU
	// df -h is Size/Used/Avail/Use%, busybox and df -P have one fewer column).
	dfHeader = compile(`^(Filesystem)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?\s+(Mounted on)\s*$`)

	// lastlogHeader anchors lastlog's columns. Its header words are mixed case
	// ("Username Port From Latest"), so the generic all-caps header test never
	// recognizes the line and the panel would cycle word by word instead.
	lastlogHeader = compile(`^(Username)\s+(Port)\s+(From)\s+(Latest)\s*$`)

	// logTrailer is an accounting store's closing line: where its records begin
	// ("wtmp begins …", "wtmpdb begins …"), or that it holds none ("… has no
	// entries"). That is a remark about the file, not a row of it, so it stays
	// plain where a session row takes the column colors.
	logTrailer = compile(`^(?:\S+ has no entries|(?:wtmp|wtmpdb|btmp) begins\b)`)
)

// columnTol is the boundary tolerance when locating a word's column against the
// header anchors: in tables aligned to their widest cell (ss and similar), a
// data column's left edge can float 1–2 characters left of the header word.
const columnTol = 2

// columnIndex locates a word's column against anchored header starts: a word
// starting inside a header interval (tolerance included) gets that column's
// index.
func columnIndex(starts []int, start int) int {
	pos, _ := slices.BinarySearch(starts, start+columnTol+1)
	return max(pos-1, 0)
}

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

func (t *tableStyler) style(line string) []paintSpan {
	if uptimeBanner.MatchString(line) {
		return []paintSpan{{Start: 0, End: len(line), Style: mutedStyle}}
	}
	if logTrailer.MatchString(line) {
		return nil
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
		t.starts = t.headerStarts(line, columns)
		return nil
	}
	if len(t.starts) == 0 {
		// A styler with declared headers knows an anchor line is coming: text
		// ahead of it (a note, a banner) stays plain, rather than taking the
		// word-by-word cycle that exists for headerless tables.
		if t.cycle && len(t.headers) == 0 {
			return cycleColumns(columns)
		}
		return nil
	}
	var spans []paintSpan
	for _, column := range columns {
		if pos := columnIndex(t.starts, column.start); pos < len(t.starts)-1 {
			spans = append(spans, paintSpan{
				Start: column.start, End: column.end,
				Style: tableColumnStyles[pos%len(tableColumnStyles)],
			})
		}
	}
	return spans
}

// headerStarts pins a header row's column anchors: a header regex with capture
// groups contributes one anchor per group (df's "Mounted on" stays a single
// column), otherwise every word anchors its own column.
func (t *tableStyler) headerStarts(line string, columns []word) []int {
	for _, header := range t.headers {
		idx := header.FindStringSubmatchIndex(line)
		if idx == nil || idx[0] != 0 {
			continue
		}
		var starts []int
		for group := 1; 2*group < len(idx); group++ {
			if idx[2*group] >= 0 {
				starts = append(starts, idx[2*group])
			}
		}
		if len(starts) >= 2 {
			return starts
		}
	}
	return lo.Map(columns, func(column word, _ int) int { return column.start })
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
func cycleColumns(columns []word) []paintSpan {
	return lo.Map(columns[:len(columns)-1], func(column word, index int) paintSpan {
		return paintSpan{
			Start: column.start, End: column.end,
			Style: tableColumnStyles[index%len(tableColumnStyles)],
		}
	})
}
