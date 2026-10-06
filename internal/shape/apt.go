// apt history shaping: history.log's records are one field per line, which
// the panel reads as prose; the story an operator wants is one row per
// transaction — when it started and the command line that ran it. The rest of
// a record (the package lists, the end date, the error text) stays in the raw
// evidence the check saves; the panel keeps the timeline.

package shape

import (
	"strings"

	"karma/internal/model"
)

// aptHistorySection is the one section this shaper rewrites; the dpkg log and
// the dnf table keep their own shapes.
const aptHistorySection = "/var/log/apt/history.log"

// AptHistory reshapes the apt history section into two columns: the start
// date, then the command line. A transaction that never wrote its command
// line (apt died mid-run) still shows its date, with the column empty.
func AptHistory(title, body string) *model.Shaped {
	if title != aptHistorySection {
		return nil
	}
	type txn struct{ date, command string }
	var txns []txn
	for _, line := range lines(body) {
		key, value, found := strings.Cut(line, ": ")
		if !found {
			continue
		}
		switch key {
		case "Start-Date":
			txns = append(txns, txn{date: strings.Join(strings.Fields(value), " ")})
		case "Commandline":
			if len(txns) > 0 && txns[len(txns)-1].command == "" {
				txns[len(txns)-1].command = value
			}
		}
	}
	if len(txns) == 0 {
		return nil
	}
	table := NewTable()
	for _, t := range txns {
		table.Add(t.date, t.command)
	}
	return shaped(table.String())
}
