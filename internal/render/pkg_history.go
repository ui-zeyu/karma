// pkg-history pseudo-lexer: the package managers' own textual records — apt's
// history entries, dpkg's log lines, and dnf's history table.
//
// The check keeps these rows with keep filters and paints them by shape: a
// record of what changed is context, not a finding, so no severity and no
// trailing reason attach to it. The colors carry the reading instead — the
// timestamp is metadata, the verb is the action, the package or the program is
// the subject, and an option is an argument.

package render

var (
	// apt's history.log carries two lines per transaction: when it started and
	// the command line that did it.
	aptHistoryLine = compile(`^(?P<key>Start-Date|Commandline):[ \t]*(?P<value>.*)$`)
	// dpkg's log line: the timestamp, the verb that changed which packages are
	// on disk, then the package and the versions it moved between.
	dpkgLogLine = compile(`^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}) ` +
		`(?P<action>install|upgrade|remove|purge) (?P<package>[^:\s]+)(?P<arch>:\S+)?(?: (?P<versions>.*))?$`)
	// A command line is words: the program first, then its arguments.
	historyWord = compile(`\S+`)
	historyFlag = compile(`^-{1,2}\S+$`)
)

// The record colors stay inside the syntax palette (the severity colors are
// reserved for hits).
var (
	historyActionStyle  = style{fg: "6"} // dark cyan, the table palette's last column
	historySubjectStyle = stringColor    // blue, the same as an identifier elsewhere
	historyArgStyle     = style{fg: "2"} // green, an option rather than an operand
	historyTailStyle    = dimStyle       // the arch suffix and the version pair
)

func stylePkgHistory(line string) []paintSpan {
	if matched, ok := matchLine(dpkgLogLine, line); ok {
		dateStart, _, _ := matched.span("date")
		_, timeEnd, _ := matched.span("time")
		actionStart, actionEnd, _ := matched.span("action")
		packageStart, packageEnd, _ := matched.span("package")
		spans := []paintSpan{
			{Start: dateStart, End: timeEnd, Style: mutedStyle},
			{Start: actionStart, End: actionEnd, Style: historyActionStyle},
			{Start: packageStart, End: packageEnd, Style: historySubjectStyle},
		}
		for _, name := range []string{"arch", "versions"} {
			if start, end, ok := matched.span(name); ok {
				spans = append(spans, paintSpan{Start: start, End: end, Style: historyTailStyle})
			}
		}
		return spans
	}
	if matched, ok := matchLine(aptHistoryLine, line); ok {
		keyStart, keyEnd, _ := matched.span("key")
		valueStart, valueEnd, _ := matched.span("value")
		// The key and its colon are the label; the date beside "Start-Date" is
		// the value and keeps the body's own color.
		spans := []paintSpan{{Start: keyStart, End: keyEnd + 1, Style: mutedStyle}}
		if line[keyStart:keyEnd] == "Commandline" {
			spans = append(spans, commandLineSpans(line, [2]int{valueStart, valueEnd})...)
		}
		return spans
	}
	// dnf answers from its own history table: ` | `-segmented rows.
	return stylePipeTable(line)
}

// commandLineSpans colors a Commandline value: the program, then its arguments
// — an option is green, an operand keeps the body color.
func commandLineSpans(line string, value [2]int) []paintSpan {
	var spans []paintSpan
	first := true
	for word := range matches(historyWord, line) {
		if word.start < value[0] {
			continue
		}
		switch {
		case first:
			spans = append(spans, paintSpan{Start: word.start, End: word.end, Style: historySubjectStyle})
			first = false
		case wholeToken(historyFlag, word.text):
			spans = append(spans, paintSpan{Start: word.start, End: word.end, Style: historyArgStyle})
		}
	}
	return spans
}
