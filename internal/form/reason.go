// The reason line: what the reading layer says about a hit, stated where the
// form puts it — under the column a table hit fell in, under the branch a tree
// node hangs from, at the end of a line of text.

package form

import (
	"fmt"

	"karma/internal/model"
)

// ReasonFor is the reason line for a set of hits: the most severe hit's
// message in angle brackets, with the count of the hits beside it. Empty when
// nothing among them is a signal, which is also what keeps a quiet row silent.
func ReasonFor(matches []model.Match) string {
	var top model.Match
	signals := 0
	for _, match := range matches {
		if !match.Severity.IsSignal() {
			continue
		}
		if signals == 0 || match.Severity < top.Severity {
			top = match
		}
		signals++
	}
	if signals == 0 {
		return ""
	}
	reason := "⟨" + top.Message + "⟩"
	if signals > 1 {
		reason += fmt.Sprintf(" +%d", signals-1)
	}
	return reason
}
