// Package reader is the reading pipeline: split sections (the `== ` convention,
// owned by internal/section), shape the body, and decide per-line visibility,
// producing the Document the presentation layer renders. Pure functions, with no
// dependency on the executor or terminal. Checks compose rules
// and filters at construction time; this consumes only the already-assembled slices.
// Filtered lines are not shown but are counted per filter. The evidence stays
// elsewhere: CheckResult.Raw is the channel's raw output, which nothing here touches.
package reader

import (
	"iter"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/samber/lo"

	"karma/internal/fault"
	"karma/internal/model"
	"karma/internal/section"
	"karma/internal/textutil"
)

// MaxScanBytes is the output cap for a single check's reading input, preventing huge files from bogging down the terminal.
const MaxScanBytes = 2 * 1024 * 1024

// belowFloor is the id the severity floor counts the rows it hides under: the
// floor is the run's own filter, and a hidden row is counted the way a filter's
// rows are, so the panel reports both in one number.
const belowFloor = "below-severity"

// Analyze reads one command output into a document.
//
// Order is fixed: byte-cap by the check's scan limit (0 uses MaxScanBytes), split
// sections by `== `, shape each body (with the section title), rule matches,
// then line filtering decides whether a body line stays. Titles run rules but are
// not filtered. transforms shape a section in the order given — a tier's dialect
// alignment first, the check's own normalization after — and either may be
// absent. floor is the run's severity floor: a row below it is counted and
// left out before the filters are consulted, so a triage run drops it whichever
// filter would have kept it. model.FloorAll keeps every row.
func Analyze(text string, rules []model.Matcher, filters []model.LineFilter, scanBytes int, floor model.SeverityFloor, transforms ...model.Normalizer) model.Document {
	capped, truncated := capBytes(text, scanBytes)
	keepFilters, dropFilters := lo.FilterReject(filters, func(f model.LineFilter, _ int) bool {
		return f.Mode == model.FilterKeep
	})

	var (
		sections []model.Section
		filtered counter
		number   int
	)
	for piece := range pieces(capped, transforms) {
		if piece.titleSet {
			number++
		}
		title := model.TextRecord(piece.title)
		titleMatches := judgeRecord(&title, rules)
		kept := make([]model.Line, 0, len(piece.lines))
		// One scratch record serves every line of text: a body with no fields of
		// its own is judged as a series of one-field records.
		var textLine model.Record
		for index, line := range piece.lines {
			number++
			rec := piece.recordAt(index, line, &textLine)
			matches := append(judgeRecord(rec, rules), piece.notes[index]...)
			severity, hid := gate(rec, matches, floor, keepFilters, dropFilters)
			if hid != "" {
				filtered = filtered.add(hid)
				continue
			}
			kept = append(kept, model.Line{
				Number:   number,
				Text:     line,
				Severity: severity,
				Matches:  matches,
				Record:   piece.structured(index),
			})
		}
		if len(kept) == 0 && len(titleMatches) == 0 {
			continue
		}
		sections = append(sections, model.Section{
			Title:        piece.title,
			TitleMatches: titleMatches,
			Lines:        kept,
			Columns:      piece.columns(),
		})
	}

	return model.Document{Sections: sections, Truncated: truncated, Filtered: filtered}
}

// capBytes truncates by UTF-8 bytes when over the reading limit, dropping the
// partial character at the cut point. A limit of zero or less (a catalog
// construction bug) uses MaxScanBytes, so Analyze is total over any int.
func capBytes(text string, limit int) (string, bool) {
	if limit <= 0 {
		limit = MaxScanBytes
	}
	if len(text) <= limit {
		return text, false
	}
	cut := text[:limit]
	// back off to a complete rune boundary: the partial bytes at the cut point are dropped entirely
	for len(cut) > 0 {
		if r, size := utf8.DecodeLastRuneInString(cut); r != utf8.RuneError || size > 1 {
			break
		}
		cut = cut[:len(cut)-1]
	}
	return cut, true
}

// gate is one record's way through the reading's two gates — the severity
// floor first, then the line filters — returning its severity and the id of
// whichever gate hid it. The order is the reading's own rule, walked by the
// text path and the records path alike: a keep filter does not rescue a row
// below the floor, and a drop filter does not hide a row above it.
func gate(rec *model.Record, matches []model.Match, floor model.SeverityFloor,
	keepFilters, dropFilters []model.LineFilter) (model.Severity, string) {
	severity := lineSeverity(matches)
	if !floor.Keeps(severity) {
		return severity, belowFloor
	}
	if id, hidden := hideReason(rec, matches, keepFilters, dropFilters); hidden {
		return severity, id
	}
	return severity, ""
}

// hideReason returns the filter id that hides the record; a visible record
// returns false.
//
// Records hit by a signal stay (signal takes priority); when keep filters
// exist, records matching no keep filter are hidden and counted under the
// first keep filter; drop filters are evaluated in declaration order.
func hideReason(rec *model.Record, matches []model.Match, keepFilters, dropFilters []model.LineFilter) (string, bool) {
	if lo.SomeBy(matches, func(m model.Match) bool { return m.Severity.IsSignal() }) {
		return "", false
	}
	if len(keepFilters) > 0 {
		if lo.SomeBy(keepFilters, func(f model.LineFilter) bool { return f.Match(rec) }) {
			return "", false
		}
		return keepFilters[0].ID, true
	}
	if f, ok := lo.Find(dropFilters, func(f model.LineFilter) bool { return f.Match(rec) }); ok {
		return f.ID, true
	}
	return "", false
}

// piece is one body after section splitting and per-section normalize.
type piece struct {
	title    string
	titleSet bool
	lines    []string
	notes    map[int][]model.Match
	// records is the same body as fields, one record per line, when the body is
	// a record set; nil for a body of ordinary text.
	records *model.RecordSet
}

// recordAt is the record a rule judges: the body's own when it arrived as
// records, a one-field record of the line itself otherwise. scratch is the
// caller's reusable record, so a body of plain text costs no allocation per
// line.
func (p piece) recordAt(index int, line string, scratch *model.Record) *model.Record {
	if p.records == nil {
		*scratch = model.Record{Fields: append(scratch.Fields[:0], model.Field{Value: line})}
		return scratch
	}
	return &p.records.Rows[index]
}

// structured is the line's record as the presentation keeps it: nil for a body
// of plain text, whose panel reads the line, not a record of one field.
func (p piece) structured(index int) *model.Record {
	if p.records == nil {
		return nil
	}
	return &p.records.Rows[index]
}

// columns is the section's record columns; nil for a body of ordinary text.
func (p piece) columns() []string {
	if p.records == nil {
		return nil
	}
	return p.records.Header
}

// pieces lazily splits and shapes sections. Without transforms it keeps the raw
// lines; with them it round-trips the text, leaving trailing blank lines to the
// shaper. Ranges given by a shaper are recorded by line number and merged with
// regex matches during the scan.
func pieces(text string, transforms []model.Normalizer) iter.Seq[piece] {
	return func(yield func(piece) bool) {
		for sec := range section.Parse(text) {
			if !yield(shaped(sec, transforms)) {
				return
			}
		}
	}
}

// shaped shapes one section body, running every transform in turn on the text
// the one before produced; a nil transform is no transform, and no transform at
// all keeps the raw lines. A transform that returns nil leaves the text as it is
// (a shaper that declines this body).
//
// If a shaper panics on odd output (a hard-coded row shape hitting the target's
// mixed output), this section uses the text as it stood then: the fallback sits
// at the panic source, so already-collected output does not fail wholesale
// because shaping panicked.
func shaped(sec section.Section, transforms []model.Normalizer) piece {
	p := piece{title: sec.Title, titleSet: sec.Marked, lines: sec.Lines}
	if !slices.ContainsFunc(transforms, func(transform model.Normalizer) bool { return transform != nil }) {
		return p
	}
	text := strings.Join(sec.Lines, "\n")
	var notes []model.LineMatch
	var records *model.RecordSet
	for _, transform := range transforms {
		if transform == nil {
			continue
		}
		result := safeNormalize(transform, p.title, text)
		if result == nil {
			continue
		}
		text = result.Text
		notes = append(notes, result.Notes...)
		// The last shaper that recognized the body states its records, as it
		// states the text they were read from.
		if result.Records != nil {
			records = result.Records
		}
	}
	p.lines = textutil.CollectLines(text)
	// The records line up with the text's lines or they are not this body's:
	// a shaper whose record count disagrees with the text it produced is not
	// something to draw half of.
	if records != nil && len(records.Rows) != len(p.lines) {
		records = nil
	}
	p.records = records
	p.notes = lo.MapValues(
		lo.GroupBy(notes, func(note model.LineMatch) int { return note.Line }),
		func(notes []model.LineMatch, _ int) []model.Match {
			return lo.Map(notes, func(note model.LineMatch, _ int) model.Match { return note.Match })
		},
	)
	return p
}

// safeNormalize insures the shaper: a panic is treated as no shaping, keeping
// the section's raw lines. The boundary is the fault package's, like every
// other one a run crosses, and it reports no error here: odd target output
// hitting a hard-coded row shape is what the fallback is for.
func safeNormalize(normalize model.Normalizer, title, body string) *model.Shaped {
	shaped, _ := fault.Result("section shaper", func() *model.Shaped { return normalize(title, body) })
	return shaped
}

// lineSeverity is the line's severity: take the highest match (severity constants
// are declared in severity order, lower wins); benign applies only when there are no
// other matches; no match is Info.
func lineSeverity(matches []model.Match) model.Severity {
	if len(matches) == 0 {
		return model.Info
	}
	severity := model.Benign
	for _, match := range matches {
		if match.Severity != model.Benign && match.Severity < severity {
			severity = match.Severity
		}
	}
	return severity
}

// judgeRecord is the judgment of one record by every rule: each rule states
// the hits it recognizes (a Matcher reads the record's fields, so a rule
// shaped around a field never has to parse a line back out), and a rule counts
// at most once per record. The result is nil when nothing matched — the common
// case on a normal host — so a quiet record allocates nothing.
func judgeRecord(rec *model.Record, matchers []model.Matcher) []model.Match {
	var matches []model.Match
	for _, matcher := range matchers {
		matches = append(matches, matcher.Judge(rec)...)
	}
	return matches
}

// AnalyzeRecords reads a body that arrived as fields: the records are the
// lines, their fields are what every rule reads, and there is no text to cap,
// split or shape — the collection already bounded the rows and the shape is
// the form's business.
func AnalyzeRecords(set *model.RecordSet, rules []model.Matcher, filters []model.LineFilter,
	floor model.SeverityFloor) model.Document {
	keepFilters, dropFilters := lo.FilterReject(filters, func(f model.LineFilter, _ int) bool {
		return f.Mode == model.FilterKeep
	})
	var (
		kept     = make([]model.Line, 0, len(set.Rows))
		filtered counter
	)
	for index := range set.Rows {
		rec := &set.Rows[index]
		line := rec.LineText()
		matches := judgeRecord(rec, rules)
		severity, hid := gate(rec, matches, floor, keepFilters, dropFilters)
		if hid != "" {
			filtered = filtered.add(hid)
			continue
		}
		kept = append(kept, model.Line{
			Number:   index + 1,
			Text:     line,
			Severity: severity,
			Matches:  matches,
			Record:   rec,
		})
	}
	document := model.Document{Filtered: filtered}
	if len(kept) == 0 {
		return document
	}
	document.Sections = []model.Section{{Lines: kept, Columns: set.Header}}
	return document
}

// counter is a filter hit count that preserves insertion order. Value semantics: add returns the updated count table.
type counter []model.FilterCount

func (c counter) add(id string) counter {
	if i := slices.IndexFunc(c, func(fc model.FilterCount) bool { return fc.ID == id }); i >= 0 {
		c[i].Count++
		return c
	}
	return append(c, model.FilterCount{ID: id, Count: 1})
}
