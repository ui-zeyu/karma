// Rule and filter prefilters: the literal a line must contain for a pattern to
// match it. Every line of every check runs the whole rule pack, and the
// regexp engine is the reading pipeline's hot path — a pattern that begins with
// \b, an alternation, or a character class gives the engine no literal to scan
// for, so it falls back to backtracking over the line. A necessary literal turns
// that into one pass over the line's bytes for the lines that cannot match.
//
// The extraction is deliberately conservative: a nil result means "no literal
// could be proven", and the pattern then always runs. It is a filter for
// speed, never a verdict — a line it rejects is a line the pattern cannot
// match, and the invariant is pinned by TestPrefilterIsNecessary over every
// pattern shape the extractor reads.

package model

import (
	"cmp"
	"regexp/syntax"
	"slices"
	"strings"
)

const (
	// maxPrefilterLiterals bounds the candidates one pattern may carry: each is
	// one scan of the line, so a pattern whose alternation names more than this
	// keeps its plain regex.
	maxPrefilterLiterals = 64
	// minPrefilterLiteral is the shortest literal worth a scan. A one-byte
	// literal costs the same as a longer one and filters almost nothing, so a
	// pattern with nothing longer keeps its plain regex.
	minPrefilterLiteral = 2
)

// prefilter compiles one pattern source into the literals a matching line must
// contain, longest first; nil means the pattern always runs. The order puts the
// most selective candidate first, since the test stops at the first hit.
func prefilter(source string) []string {
	parsed, err := syntax.Parse(source, syntax.Perl)
	if err != nil {
		return nil
	}
	literals := requiredLiterals(parsed.Simplify())
	slices.Sort(literals)
	literals = slices.Compact(literals)
	if len(literals) == 0 || len(literals) > maxPrefilterLiterals {
		return nil
	}
	slices.SortFunc(literals, func(a, b string) int {
		return cmp.Or(cmp.Compare(len(b), len(a)), strings.Compare(a, b))
	})
	if len(literals[0]) < minPrefilterLiteral {
		return nil
	}
	return literals
}

// matches reports whether the line can hold a match: a line missing every
// literal cannot match, and one holding any of them goes to the regexp engine
// for the verdict.
func prefilterMatches(literals []string, line string) bool {
	if len(literals) == 0 {
		return true
	}
	return slices.ContainsFunc(literals, func(literal string) bool {
		return strings.Contains(line, literal)
	})
}

// requiredLiterals returns literals such that a text matched by re contains at
// least one of them; nil means none could be proven. The proof is local to each
// node and holds for the empty text as well, so a node that can match nothing
// (a repetition with a zero minimum, an optional group, an empty match) yields
// nil rather than a literal it is not obliged to contain.
func requiredLiterals(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		// A case-folded literal has no fixed spelling; an empty one is no
		// constraint either.
		if re.Flags&syntax.FoldCase != 0 || len(re.Rune) == 0 {
			return nil
		}
		return []string{string(re.Rune)}
	case syntax.OpCapture, syntax.OpPlus:
		if len(re.Sub) != 1 {
			return nil
		}
		return requiredLiterals(re.Sub[0])
	case syntax.OpRepeat:
		// A minimum of zero may match empty, so nothing is owed.
		if re.Min == 0 || len(re.Sub) != 1 {
			return nil
		}
		return requiredLiterals(re.Sub[0])
	case syntax.OpConcat:
		// Every part matched, so any one part's literal proves the whole;
		// the most selective part is kept.
		var best []string
		for _, sub := range re.Sub {
			if set := requiredLiterals(sub); moreSelective(set, best) {
				best = set
			}
		}
		return best
	case syntax.OpAlternate:
		// One branch matched, so every branch must carry a literal: a branch
		// without one leaves the alternation unprovable.
		var out []string
		for _, sub := range re.Sub {
			set := requiredLiterals(sub)
			if len(set) == 0 {
				return nil
			}
			out = append(out, set...)
		}
		return out
	}
	return nil
}

// moreSelective reports whether set filters better than best: the longest
// literal decides (a longer string is a rarer one to scan for), and among
// equally long ones the smaller candidate list wins.
func moreSelective(set, best []string) bool {
	return len(set) > 0 && cmp.Or(longestLiteral(set)-longestLiteral(best), len(best)-len(set)) > 0
}

func longestLiteral(set []string) int {
	longest := 0
	for _, literal := range set {
		longest = max(longest, len(literal))
	}
	return longest
}
