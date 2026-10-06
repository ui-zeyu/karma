// Package reader is the reading pipeline: split sections, shape the body, and decide
// per-line visibility, producing the Document the presentation layer renders. Pure
// functions, with no dependency on the executor or terminal. Checks compose rules
// and filters at construction time; this consumes only the already-assembled slices.
// Filtered lines are not shown but are counted per filter. Evidence is kept elsewhere:
// the text written by --save is the channel's raw output, so nothing here touches it.
package reader

import (
	"iter"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/samber/lo"

	"karma/internal/model"
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
// sections by `== `, normalize each body (with the section title), rule matches,
// then line filtering decides whether a body line stays. Titles run rules but are
// not filtered. floor is the run's severity floor: a row below it is counted and
// left out before the filters are consulted, so a triage run drops it whichever
// filter would have kept it. model.FloorAll keeps every row.
func Analyze(text string, rules []model.Rule, filters []model.LineFilter, normalize model.Normalizer, scanBytes int, floor model.SeverityFloor) model.Document {
	capped, truncated := capBytes(text, scanBytes)
	keepFilters, dropFilters := lo.FilterReject(filters, func(f model.LineFilter, _ int) bool {
		return f.Mode == model.FilterKeep
	})

	var (
		sections []model.Section
		filtered counter
		number   int
	)
	for piece := range pieces(capped, normalize) {
		if piece.titleSet {
			number++
		}
		titleMatches := lineMatches(piece.title, rules)
		kept := make([]model.Line, 0, len(piece.lines))
		for index, line := range piece.lines {
			number++
			matches := append(lineMatches(line, rules), piece.notes[index]...)
			severity := lineSeverity(matches)
			if !floor.Keeps(severity) {
				filtered = filtered.add(belowFloor)
				continue
			}
			if id, hidden := hideReason(line, matches, keepFilters, dropFilters); hidden {
				filtered = filtered.add(id)
				continue
			}
			kept = append(kept, model.Line{
				Number:   number,
				Text:     line,
				Severity: severity,
				Matches:  matches,
			})
		}
		if len(kept) == 0 && len(titleMatches) == 0 {
			continue
		}
		sections = append(sections, model.Section{
			Title:        piece.title,
			TitleMatches: titleMatches,
			Lines:        kept,
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

// hideReason returns the filter id that hides the line; a visible line returns false.
//
// Lines hit by a signal stay (signal takes priority); when keep filters exist, lines
// matching no keep filter are hidden and counted under the first keep filter; drop
// filters are evaluated in declaration order.
func hideReason(line string, matches []model.Match, keepFilters, dropFilters []model.LineFilter) (string, bool) {
	if lo.SomeBy(matches, func(m model.Match) bool { return m.Severity.IsSignal() }) {
		return "", false
	}
	if len(keepFilters) > 0 {
		if lo.SomeBy(keepFilters, func(f model.LineFilter) bool { return f.Match(line) }) {
			return "", false
		}
		return keepFilters[0].ID, true
	}
	if f, ok := lo.Find(dropFilters, func(f model.LineFilter) bool { return f.Match(line) }); ok {
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
}

// pieces lazily splits and shapes sections. Without normalize it keeps the raw lines;
// with normalize it round-trips the text, leaving trailing blank lines to the shaper.
// Ranges given by the shaper are recorded by line number and merged with regex
// matches during the scan.
func pieces(text string, normalize model.Normalizer) iter.Seq[piece] {
	return func(yield func(piece) bool) {
		for section := range splitSections(text) {
			if !yield(section.shaped(normalize)) {
				return
			}
		}
	}
}

type rawSection struct {
	title    string
	titleSet bool
	lines    []string
}

// shaped shapes one section body; a nil shaper keeps the raw lines. If the shaper
// panics on odd output (a hard-coded row shape hitting the target's mixed output),
// this section uses the original text: the fallback sits at the panic source, so
// already-collected output does not fail wholesale because shaping panicked.
func (s rawSection) shaped(normalize model.Normalizer) piece {
	p := piece{title: s.title, titleSet: s.titleSet, lines: s.lines}
	if normalize == nil {
		return p
	}
	result := safeNormalize(normalize, p.title, strings.Join(s.lines, "\n"))
	if result == nil {
		return p
	}
	p.lines = textutil.CollectLines(result.Text)
	p.notes = lo.MapValues(
		lo.GroupBy(result.Notes, func(note model.LineMatch) int { return note.Line }),
		func(notes []model.LineMatch, _ int) []model.Match {
			return lo.Map(notes, func(note model.LineMatch, _ int) model.Match { return note.Match })
		},
	)
	return p
}

// safeNormalize insures the shaper: on panic it is treated as no shaping, keeping the section's raw lines.
func safeNormalize(normalize model.Normalizer, title, body string) (shaped *model.Shaped) {
	defer func() {
		if recover() != nil {
			shaped = nil
		}
	}()
	return normalize(title, body)
}

// splitSections lazily cuts on `== ` lines. Lines before the first marker are the
// preamble (titleSet false); empty text has no sections.
func splitSections(text string) iter.Seq[rawSection] {
	return func(yield func(rawSection) bool) {
		var current rawSection
		started := false
		for line := range textutil.Lines(text) {
			if head, ok := strings.CutPrefix(line, "== "); ok {
				if started && !yield(current) {
					return
				}
				current, started = rawSection{title: head, titleSet: true}, true
				continue
			}
			current.lines = append(current.lines, line)
			started = true
		}
		if started {
			yield(current)
		}
	}
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

// lineMatches is the first match of each rule within a line; each rule counts at
// most once per line. The result is nil when nothing matched — the common case
// on a normal host — so a quiet line allocates nothing for the rules that did
// not hit.
func lineMatches(line string, rules []model.Rule) []model.Match {
	var matches []model.Match
	for _, r := range rules {
		start, end, ok := r.Find(line)
		if !ok {
			continue
		}
		matches = append(matches, model.Match{
			ID: r.ID, Severity: r.Severity, Message: r.Message, Start: start, End: end,
		})
	}
	return matches
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
