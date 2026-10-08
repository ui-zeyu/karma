// Rules and filters: the patterns a record is judged by, and the two ways a
// line is hidden.

package model

import "regexp"

// FilterMode is the direction of a line filter: Drop removes matching lines,
// Keep shows only matching lines (allowlist).
type FilterMode int

const (
	FilterDrop FilterMode = iota
	FilterKeep
)

// Rule is one pattern rule: the pattern runs over every field's value of the
// record, and a value it matches states the hit where it fell. Exclude is the
// value-level exclusion — RE2 has no lookaround, so "does not match this
// prefix/shape" lives in this field; a hit requires Pattern to match and the
// value it matched to clear Exclude. Exclusion is per value because the rules
// that use it match per-path output: the path is one field's value.
type Rule struct {
	ID       string
	Pattern  *regexp.Regexp
	Severity Severity
	Message  string
	Exclude  *regexp.Regexp
	// literals is the prefilter of Pattern (see prefilter.go): the strings a
	// value must contain for Pattern to match it, empty when none could be
	// proven. It is derived here so no caller can forget it.
	literals []string
}

// NewRule compiles the regex and builds a Rule; a bad regex fails during
// catalog construction.
// Case insensitivity is written into the pattern itself ((?i)).
func NewRule(id, pattern string, severity Severity, message string) Rule {
	return Rule{
		ID:       id,
		Pattern:  regexp.MustCompile(pattern),
		Severity: severity,
		Message:  message,
		literals: prefilter(pattern),
	}
}

// WithExclude attaches a value-level exclusion and returns a copy.
func (r Rule) WithExclude(exclude string) Rule {
	r.Exclude = regexp.MustCompile(exclude)
	return r
}

// LineFilter is one record filter. Drop: matching records are not shown; Keep:
// only matching records are shown (allowlist). The pattern runs over each
// field's value, any one of them, so a body of text — a one-field record —
// keeps the line filter it always was. Exclude has the same meaning as on
// Rule.
type LineFilter struct {
	ID      string
	Pattern *regexp.Regexp
	Mode    FilterMode
	Exclude *regexp.Regexp
	// literals is Pattern's prefilter, as on Rule.
	literals []string
}

// NewFilter compiles the regex and builds a record filter; a bad regex fails
// during catalog construction.
func NewFilter(id, pattern string, mode FilterMode) LineFilter {
	return LineFilter{
		ID:       id,
		Pattern:  regexp.MustCompile(pattern),
		Mode:     mode,
		literals: prefilter(pattern),
	}
}

// WithExclude attaches a value-level exclusion and returns a copy.
func (f LineFilter) WithExclude(exclude string) LineFilter {
	f.Exclude = regexp.MustCompile(exclude)
	return f
}

// Match reports whether the record is a hit: a value that clears the
// prefilter, matches the pattern, and clears the exclusion. A record whose
// every value misses is not a hit, and a value the exclusion matches does not
// count for the ones beside it.
func (f LineFilter) Match(rec *Record) bool {
	for _, field := range rec.Fields {
		if !prefilterMatches(f.literals, field.Value) {
			continue
		}
		if !f.Pattern.MatchString(field.Value) {
			continue
		}
		return f.Exclude == nil || !f.Exclude.MatchString(field.Value)
	}
	return false
}

// Match is one hit plus its conclusion. Regex hits and conclusions the
// normalizer states up front (listing outliers) are both Match: the spans,
// severity, and reason are fixed where they are produced, and filtering and
// rendering never read the rule back.
type Match struct {
	ID       string
	Severity Severity
	Message  string
	// Spans is where the hit fell: one span per field it recognized, in that
	// field's own value. Empty means the hit belongs to the record itself —
	// the row, the node, the line — and a form paints it whole.
	Spans []Span
}
