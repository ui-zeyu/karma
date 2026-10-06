// dmesg pseudo-lexer: the leading wall-clock timestamp is muted.

package render

var dmesgTS = compile(`^\[\s*\d+\.\d+\]\s`)

func styleDmesg(line string) []paintSpan {
	if matched := dmesgTS.FindStringIndex(line); matched != nil {
		return []paintSpan{{Start: matched[0], End: matched[1], Style: mutedStyle}}
	}
	return nil
}
