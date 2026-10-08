// os-release shaping: the distro file's KEY=VALUE lines become the two columns
// the check's form draws, and every other line — the kernel line the same tier
// appends, the blank between them — becomes a record that states the line
// itself, which the form prints as the remark it is.

package shape

import (
	"strings"

	"karma/internal/model"
)

// OsReleaseColumns is os-release(5)'s record as karma spells it: the file's own
// key, and the value the shell would end up with.
var OsReleaseColumns = []string{"Key", "Value"}

// OsRelease reads an os-release body into records: every KEY=VALUE line is one
// setting, and the kernel line the tier appends under it is the file's
// companion fact rather than a setting of its own.
//
// A line that is not a setting keeps its own bytes as a one-value record, which
// the form draws as the line it is rather than as a row with one cell filled —
// the same way fstab's remarks read. A body with no setting at all is declined
// whole: lsb_release's colon-separated fallback is not this table, and it stays
// the text the tool wrote.
func OsRelease(title, body string) *model.Shaped {
	rows := lines(body)
	set := &model.RecordSet{Header: OsReleaseColumns}
	settings := 0
	for _, row := range rows {
		key, value, ok := osReleaseSetting(row)
		if !ok {
			set.Rows = append(set.Rows, model.Record{
				Fields: []model.Field{{Value: strings.TrimSuffix(row, "\r")}},
			})
			continue
		}
		set.Rows = append(set.Rows, model.Record{Fields: []model.Field{
			{Name: OsReleaseColumns[0], Value: key},
			{Name: OsReleaseColumns[1], Value: value},
		}})
		settings++
	}
	if settings == 0 {
		return nil
	}
	return shapedRecords(strings.Join(rows, "\n")+"\n", set)
}

// osReleaseSetting cuts one KEY=VALUE line: the name as the file spells it, and
// the value with the quoting a shell would take off it. A line whose name is not
// an os-release name — a comment, a colon-separated line from lsb_release, prose
// — is not one of the file's settings.
func osReleaseSetting(line string) (string, string, bool) {
	key, value, found := strings.Cut(strings.TrimSuffix(line, "\r"), "=")
	if !found || !osReleaseName(key) {
		return "", "", false
	}
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		value = value[1 : len(value)-1]
	}
	return key, value, true
}

// osReleaseName reports whether a name is one os-release(5) allows: uppercase
// letters, digits and underscores, starting with a letter. The strict spelling is
// what keeps a prose line carrying an '=' — and a commented-out setting — out of
// the table instead of in it as a row.
func osReleaseName(name string) bool {
	for index, r := range name {
		switch {
		case 'A' <= r && r <= 'Z', r == '_':
		case index > 0 && '0' <= r && r <= '9':
		default:
			return false
		}
	}
	return name != ""
}
