// sshd-config pseudo-lexer: the directive name at line start is lit blue.

package render

var sshdDirm = compile(`^[ \t]*[A-Za-z][A-Za-z0-9-]*`)

func styleSshdConfig(line string) []paintSpan {
	// "directive at line start, then value" form: only the directive name is lit
	// (blue) and the value stays at the default color — a field of bright
	// magenta would read as the severity red
	if matched := sshdDirm.FindStringIndex(line); matched != nil {
		return []paintSpan{{Start: matched[0], End: matched[1], Style: style{fg: "4"}}}
	}
	return nil
}
