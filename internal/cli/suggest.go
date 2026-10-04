// Close-name suggestions for a mistyped word: one Levenshtein distance, two
// policies — a command gets the nearest name only, a selector gets up to three
// candidates within a short distance, prefix matches first.

package cli

import (
	"slices"
	"strings"

	"github.com/samber/lo"
)

// closestName keeps only the candidates with the smallest edit distance: a
// one-letter typo such as lst should suggest list, without dragging in the
// farther ssh.
func closestName(name string, candidates []string) []string {
	if len(candidates) == 0 {
		return nil
	}
	distances := lo.Map(candidates, func(candidate string, _ int) int {
		return editDistance(name, candidate)
	})
	best := slices.Min(distances)
	return lo.Filter(candidates, func(_ string, index int) bool {
		return distances[index] == best
	})
}

// closeMatches is the " Did you mean: a, b" tail for an unknown word: prefix
// hits first, then anything within edit distance 2, at most three. The tail is
// empty when nothing is close, so the message then states the unknown word and
// stops rather than promising a suggestion of "none".
func closeMatches(word string, names []string) string {
	candidates := lo.Filter(names, func(name string, _ int) bool {
		return strings.HasPrefix(name, word) || editDistance(word, name) <= 2
	})
	if len(candidates) == 0 {
		return ""
	}
	slices.SortStableFunc(candidates, func(a, b string) int {
		return prefixRank(word, a) - prefixRank(word, b)
	})
	return ". Did you mean: " + strings.Join(candidates[:min(3, len(candidates))], ", ")
}

// prefixRank orders candidates: a prefix hit (rank 0) sorts before the rest.
func prefixRank(word, name string) int {
	if strings.HasPrefix(name, word) {
		return 0
	}
	return 1
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
