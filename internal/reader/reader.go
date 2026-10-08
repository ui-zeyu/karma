// Package reader is the reading pipeline: shape each section the collection
// produced, and decide per-line visibility, producing the Document the
// presentation layer renders. Read is the entry point — one body in, one
// document out, whether a section arrived as text or as fields. Pure functions,
// with no dependency on the executor or terminal. Checks compose rules and
// filters at construction time; this consumes only the already-assembled
// slices. Filtered lines are not shown but are counted per
// filter. The evidence stays elsewhere: CheckResult.Raw is the body as the
// collection stated it, which nothing here reads back — Evidence renders a body
// as that text for the runner.
//
// Sections arrive already named (model.BodySection): a boundary is the
// collection's own statement about what it read, so no byte of file content or
// tool output can become one. A section that carries several named parts of one
// computation says so the same way (BodySection.Titles), and the reading opens a
// section at each name.
package reader

import (
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

// Read is one body's reading: the winning step's sections, in order, from the
// tier's own join over them to the document the presentation draws. A section
// that arrived as fields takes the records path; text takes the text path, where
// the step's dialect alignment and the check's own normalization shape it before
// the rules run over it.
//
// The byte cap is the reading's own, spent across the sections in order: a body
// of many files is bounded like a body of one.
//
// The source-side cut travels into the document here, because a panel marks a
// body a row cap stopped, and only the channel knows that happened.
func Read(req model.ReadRequest) model.Document {
	var (
		sections  []model.Section
		filtered  counter
		number    int
		truncated bool
		budget    = scanBudget(req.Check.ScanBytes)
	)
	for _, body := range req.Body.Sections {
		// The byte cap is the body's, spent across its sections in order: a
		// section the budget cannot cover is not read, and the body is marked cut,
		// the way a cut text lost its remainder.
		if budget <= 0 {
			truncated = true
			continue
		}
		text, cut := capBytes(body.Text, budget)
		budget -= len(text)
		truncated = truncated || cut
		// The tier's own join reduces its marked stream to rows, after the cap
		// stopped the stream and before the reading shapes it: the stream is the
		// evidence, the rows are what is read.
		if body.Assemble != nil && !cut {
			text = body.Assemble(text)
		}
		for _, part := range titledSections(body, text) {
			section, hits, next, ok := readSection(part, part.Text, req.Check, req.Floor, number)
			number = next
			filtered = filtered.merge(hits)
			if ok {
				sections = append(sections, section)
			}
		}
	}
	return model.Document{
		Sections:  sections,
		Truncated: truncated || req.Truncated,
		Filtered:  filtered,
	}
}

// titledSections splits one section into the sections its own titles name: a
// line equal to a declared title opens a section titled with it, and the text
// before the first one — if any — stays under the section's own title. A section
// with no declared titles is the one section it already is.
//
// The parts are read exactly as the whole would have been: every line keeps its
// own bytes, the title line becomes the section's title rather than a row, and a
// trailing part with nothing under it and no title of its own drops out.
func titledSections(body model.BodySection, text string) []model.BodySection {
	if len(body.Titles) == 0 {
		body.Text = text
		return []model.BodySection{body}
	}
	parts := make([]model.BodySection, 0, len(body.Titles)+1)
	// The join already ran over the whole body, so no part runs it again.
	part := body
	part.Text, part.Titles, part.Assemble = "", nil, nil
	var lines strings.Builder
	flush := func() {
		part.Text = lines.String()
		if part.Title != "" || part.Text != "" {
			parts = append(parts, part)
		}
		lines.Reset()
	}
	for line := range textutil.Lines(text) {
		if title, ok := declaredTitle(body.Titles, line); ok {
			flush()
			part = body
			part.Titles, part.Assemble, part.Title = nil, nil, title
			continue
		}
		lines.WriteString(line + "\n")
	}
	flush()
	return parts
}

// declaredTitle reports whether a body line is one of the section titles the
// collection declared, and returns it.
func declaredTitle(titles []string, line string) (string, bool) {
	for _, title := range titles {
		if line == title {
			return title, true
		}
	}
	return "", false
}

// readSection is one section's reading: the records path when the section
// arrived as fields, the text path otherwise. number is the body's running line
// number, which a titled section spends one of; ok is false when the section
// kept nothing to show.
func readSection(body model.BodySection, capped string, check *model.Check,
	floor model.SeverityFloor, number int) (model.Section, counter, int, bool) {
	// The tier's dialect alignment first — it only produces text, and stating
	// spans up front is the check-level normalizer's job — then the check's own
	// normalization, which runs on every source's answer.
	var shapers []model.Normalizer
	if body.Adapt != nil {
		shapers = append(shapers, body.Adapt)
	}
	if check.Normalize != nil {
		shapers = append(shapers, check.Normalize)
	}
	// One walk for both ways a section arrives: the gates below judge a record
	// and keep a line whichever the walk hands out, so the floor-then-filters
	// order has one statement rather than one per path.
	walk := newSectionWalk(body, body.Title, capped, shapers)
	titleRecord := model.TextRecord(body.Title)
	titleMatches := judgeRecord(&titleRecord, check.Rules)
	if body.Title != "" {
		number++
	}
	keepFilters, dropFilters := splitFilters(check.Filters)
	kept := make([]model.Line, 0, walk.count)
	var filtered counter
	for index := range walk.count {
		line := walk.line(index)
		number++
		matches := append(judgeRecord(line.record, check.Rules), line.notes...)
		severity, hid := gate(line.record, matches, floor, keepFilters, dropFilters)
		if hid != "" {
			filtered = filtered.add(hid)
			continue
		}
		kept = append(kept, model.Line{
			Number:   number,
			Text:     line.text,
			Severity: severity,
			Matches:  matches,
			Record:   line.keep,
		})
	}
	if len(kept) == 0 && len(titleMatches) == 0 {
		return model.Section{}, filtered, number, false
	}
	return model.Section{
		Title:        body.Title,
		TitleMatches: titleMatches,
		Lines:        kept,
		Columns:      walk.columns,
	}, filtered, number, true
}

// sectionLine is one line of a section as the reading walks it: the record the
// rules judge, the text a panel draws, and the record the presentation keeps —
// nil for a body of plain text, whose panel reads the line rather than a record
// of one field. notes are the shaping notes that landed on this line.
type sectionLine struct {
	record *model.Record
	text   string
	keep   *model.Record
	notes  []model.Match
}

// sectionWalk is one section's lines in reading order, whichever way the section
// arrived: the records the collection stated, or the text the shapers produced.
// Only the shaping that produced the lines knows the column names the section's
// form draws by and how many lines there are.
type sectionWalk struct {
	columns []string
	count   int
	// Exactly one of set and text is set. set is the records path. text, notes
	// and records are the text path's shaped body: records is non-nil when a
	// shaper recognized the lines and stated the fields behind them, which is
	// what lets a text tier reach the form.
	set     *model.RecordSet
	text    []string
	notes   map[int][]model.Match
	records *model.RecordSet
	// scratch is the one record a body of plain text is judged as, line by
	// line: a body with no fields of its own is a series of one-field records.
	scratch model.Record
}

// line is the index'th line as the reading walks it.
func (w *sectionWalk) line(index int) sectionLine {
	if w.set != nil {
		rec := &w.set.Rows[index]
		return sectionLine{record: rec, text: rec.LineText(), keep: rec}
	}
	text := w.text[index]
	return sectionLine{
		record: textRecord(w.records, index, text, &w.scratch),
		text:   text,
		keep:   structured(w.records, index),
		notes:  w.notes[index],
	}
}

// newSectionWalk builds the walk for one section: the records the collection
// stated, or the text the shapers produced.
func newSectionWalk(body model.BodySection, title, capped string, shapers []model.Normalizer) *sectionWalk {
	if set := body.Records; set != nil {
		return &sectionWalk{set: set, columns: set.Header, count: len(set.Rows)}
	}
	text, notes, records := shape(title, capped, shapers)
	return &sectionWalk{
		text:    text,
		notes:   notes,
		records: records,
		columns: columns(records),
		count:   len(text),
	}
}

// Evidence is one body as the record of what the target sent: the title of each
// section on its own header line, then what the section answered with — its text
// as it stands, or the fields rendered as the lines they read as. The header is
// the report's spelling of a section (internal/section); nothing parses it back.
func Evidence(body model.Body) string {
	var b strings.Builder
	for _, part := range body.Sections {
		if part.Title != "" {
			b.WriteString(section.Line(part.Title))
		}
		if part.Records != nil {
			b.WriteString(model.RecordsText(part.Records.Rows))
			continue
		}
		b.WriteString(part.Text)
	}
	return b.String()
}

// capBytes truncates by UTF-8 bytes when over the reading limit, dropping the
// partial character at the cut point. A limit of zero or less (a catalog
// construction bug) uses MaxScanBytes, so the reading is total over any int.
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

// scanBudget is the reading's byte budget: the check's own limit, or the default.
func scanBudget(scanBytes int) int {
	if scanBytes <= 0 {
		return MaxScanBytes
	}
	return scanBytes
}

// splitFilters separates the filters by mode once per section.
func splitFilters(filters []model.LineFilter) (keep, drop []model.LineFilter) {
	return lo.FilterReject(filters, func(f model.LineFilter, _ int) bool {
		return f.Mode == model.FilterKeep
	})
}

// shape runs the section's shapers in order, on the text each one produced. With
// no shaper the body keeps its raw lines. A shaper that returns nil declines the
// body, and the last one that recognized it states the records the lines were
// read from.
//
// If a shaper panics on odd output (a hard-coded row shape hitting the target's
// mixed output), this section uses the text as it stood then: the fallback sits
// at the panic source, so already-collected output does not fail wholesale
// because shaping panicked.
func shape(title, text string, shapers []model.Normalizer) ([]string, map[int][]model.Match, *model.RecordSet) {
	if !slices.ContainsFunc(shapers, func(shaper model.Normalizer) bool { return shaper != nil }) {
		return textutil.CollectLines(text), nil, nil
	}
	var notes []model.LineMatch
	var records *model.RecordSet
	for _, shaper := range shapers {
		if shaper == nil {
			continue
		}
		result := safeNormalize(shaper, title, text)
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
	lines := textutil.CollectLines(text)
	// The records line up with the text's lines or they are not this body's:
	// a shaper whose record count disagrees with the text it produced is not
	// something to draw half of.
	if records != nil && len(records.Rows) != len(lines) {
		records = nil
	}
	if len(notes) == 0 {
		return lines, nil, records
	}
	return lines, lo.MapValues(
		lo.GroupBy(notes, func(note model.LineMatch) int { return note.Line }),
		func(notes []model.LineMatch, _ int) []model.Match {
			return lo.Map(notes, func(note model.LineMatch, _ int) model.Match { return note.Match })
		},
	), records
}

// safeNormalize insures the shaper: a panic is treated as no shaping, keeping
// the section's raw lines. The boundary is the fault package's, like every
// other one a run crosses, and it reports no error here: odd target output
// hitting a hard-coded row shape is what the fallback is for.
func safeNormalize(normalize model.Normalizer, title, body string) *model.Shaped {
	shaped, _ := fault.Result("section shaper", func() *model.Shaped { return normalize(title, body) })
	return shaped
}

// textRecord is the record a rule judges: the section's own when it arrived as
// records, a one-field record of the line itself otherwise. scratch is the
// caller's reusable record, so a body of plain text costs no allocation per
// line.
func textRecord(records *model.RecordSet, index int, line string, scratch *model.Record) *model.Record {
	if records == nil {
		*scratch = model.Record{Fields: append(scratch.Fields[:0], model.Field{Value: line})}
		return scratch
	}
	return &records.Rows[index]
}

// structured is the line's record as the presentation keeps it: nil for a body
// of plain text, whose panel reads the line, not a record of one field.
func structured(records *model.RecordSet, index int) *model.Record {
	if records == nil {
		return nil
	}
	return &records.Rows[index]
}

// columns is the section's record columns; nil for a body of ordinary text.
func columns(records *model.RecordSet) []string {
	if records == nil {
		return nil
	}
	return records.Header
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

// counter is a filter hit count that preserves insertion order. Value semantics: add returns the updated count table.
type counter []model.FilterCount

// add counts one more line hidden by filter id.
func (c counter) add(id string) counter {
	return c.bump(model.FilterCount{ID: id, Count: 1})
}

// merge folds another counter into this one, keeping this one's order: an id
// already counted keeps its place, and one this table has not seen is appended.
func (c counter) merge(other counter) counter {
	for _, fc := range other {
		c = c.bump(fc)
	}
	return c
}

// bump folds one filter's count into the table.
func (c counter) bump(fc model.FilterCount) counter {
	if i := slices.IndexFunc(c, func(entry model.FilterCount) bool { return entry.ID == fc.ID }); i >= 0 {
		c[i].Count += fc.Count
		return c
	}
	return append(c, fc)
}
