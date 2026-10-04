// Selector parsing: aspect names or check ids, with commas and spaces
// equivalent. local, ssh, and list share this parser.
package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/samber/lo"

	"karma/internal/model"
)

// SelectorTokens expands one command-line word into individual selector words,
// with commas and spaces equivalent.
func SelectorTokens(raw []string) []string {
	words := lo.FlatMap(raw, func(item string, _ int) []string {
		return strings.Fields(strings.ReplaceAll(item, ",", " "))
	})
	return lo.Compact(words)
}

// SelectChecks returns the selected checks in catalog order; an aspect name
// expands to every check of that aspect.
//
// The word order does not affect the output order; an empty slice means all of
// them. An aspect word counts only if it exists in this catalog (selecting a
// Windows aspect word on the Linux catalog reports it as unknown), and an
// unknown word returns an error carrying close names for the caller to show.
func SelectChecks(tokens []string, catalog []*model.Check) ([]*model.Check, error) {
	wanted := SelectorTokens(tokens)
	if len(wanted) == 0 {
		return catalog, nil
	}

	knownIDs := lo.SliceToMap(catalog, func(c *model.Check) (string, bool) { return c.ID, true })
	catalogAspects := lo.SliceToMap(catalog, func(c *model.Check) (model.Aspect, bool) { return c.Aspect, true })
	names := slices.Concat(model.AspectNames(), lo.Keys(knownIDs))
	slices.Sort(names)

	wantedIDs := map[string]bool{}
	aspects := map[model.Aspect]bool{}
	for _, word := range wanted {
		aspect, isAspect := model.AspectByName(word)
		switch {
		case isAspect && catalogAspects[aspect]:
			aspects[aspect] = true
		case knownIDs[word]:
			wantedIDs[word] = true
		default:
			return nil, fmt.Errorf("unknown selector %q. Did you mean: %s", word, closeMatches(word, names))
		}
	}
	return lo.Filter(catalog, func(c *model.Check, _ int) bool {
		return wantedIDs[c.ID] || aspects[c.Aspect]
	}), nil
}

// closeMatches lists close names: prefix hits first, then anything within edit
// distance 2, at most three.
func closeMatches(word string, names []string) string {
	candidates := lo.Filter(names, func(name string, _ int) bool {
		return strings.HasPrefix(name, word) || editDistance(word, name) <= 2
	})
	if len(candidates) == 0 {
		return "none"
	}
	return strings.Join(candidates[:min(3, len(candidates))], ", ")
}

// editDistance is the Levenshtein distance with two rolling rows: prev is the
// previous row, curr the current one.
func editDistance(a, b string) int {
	ar, br := []rune(a), []rune(b)
	prev := make([]int, len(br)+1)
	curr := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		curr[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			curr[j] = min(min(curr[j-1]+1, prev[j]+1), prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[len(br)]
}
