// env pseudo-lexer: KEY=value rows, only the = is lit.

package render

var envName = compile(`^[A-Za-z_][A-Za-z0-9_]*=`)

func styleEnv(line string) []paintSpan {
	if matched := envName.FindStringIndex(line); matched != nil {
		// Paint only the = separating key and value and keep both sides at the
		// default color — painting the whole line reads as an alert
		return []paintSpan{{Start: matched[1] - 1, End: matched[1], Style: style{FG: "5"}}}
	}
	return nil
}
