// The web access-log body: what a request log says before anyone reads it line
// by line — the clients that hammered the host, the minutes they did it in, and
// the request lines that carry an exploit shape.
//
// Two implementations render that body and must agree byte for byte: this
// file's Go side (AccessLogBody, the local channel) and the awk pass the ssh
// and ttyd channels run (AccessLogScript). The check's test runs both over one
// fixture log and compares them.
//
// The counting rule, in both implementations: a line contributes its first
// blank-separated field as its client and its fourth field (minus a leading
// bracket, cut to 17 bytes) as its minute; a line whose lowercased text matches
// the caller's keep pattern is a request line, capped in file order. The two
// tables are ordered by count descending and then by key ascending, which is a
// total order on distinct keys, so awk's unspecified array iteration cannot
// change the answer.

package script

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"karma/internal/section"
)

// AccessLogWindow is how much of a log file the summary is built from: the tail
// is where the latest intrusion is, and a window bounds the work on a host
// whose log has grown for years. The local tier reads the same window the
// pipeline's tail does.
const AccessLogWindow = 16 << 20

// The table sizes and the cap on the request lines.
const (
	accessLogTopClients = 10
	accessLogTopMinutes = 5
	accessLogHits       = 50
)

// accessLogAwk is the one pass both tables and the request lines are collected
// in; the keep pattern and the three sizes are spliced in, so the program text
// carries none of the vocabulary.

// AccessLogScript is the ssh and ttyd channels' tier: one summary per existing
// log file, built from the file's tail by the target's own awk. keep is the Go
// side's pattern; its slashes are escaped for the awk regex literal it becomes,
// and awk reads the line lowercased, the mirror of AccessLogBody's (?i).

// AccessLogBody renders one log file's summary from its tail, the Go side of
// accessLogAwk. A file with no lines (or only blank ones) renders nothing, so
// an absent log leaves no section behind.
func AccessLogBody(path string, lines []string, keep *regexp.Regexp) string {
	clients := map[string]int{}
	minutes := map[string]int{}
	var hits []string
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		clients[fields[0]]++
		if len(fields) >= 4 {
			key := strings.TrimPrefix(fields[3], "[")
			if len(key) > 17 {
				key = key[:17]
			}
			if key != "" {
				minutes[key]++
			}
		}
		if len(hits) < accessLogHits && keep.MatchString(asciiLower(line)) {
			hits = append(hits, line)
		}
	}
	if len(clients) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(section.Line(path))
	b.WriteString("clients\n")
	writeTop(&b, clients, accessLogTopClients)
	b.WriteString("minutes\n")
	writeTop(&b, minutes, accessLogTopMinutes)
	if len(hits) > 0 {
		b.WriteString("requests\n")
		for _, hit := range hits {
			b.WriteString(hit + "\n")
		}
	}
	return b.String()
}

// writeTop renders one table: the limit highest counts first, ties broken by
// key, each row padded the way the awk pass pads it.
func writeTop(b *strings.Builder, counts map[string]int, limit int) {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b string) int {
		return cmp.Or(cmp.Compare(counts[b], counts[a]), strings.Compare(a, b))
	})
	if len(keys) > limit {
		keys = keys[:limit]
	}
	for _, key := range keys {
		fmt.Fprintf(b, "%6d %s\n", counts[key], key)
	}
}

// asciiLower is awk's tolower under LC_ALL=C: only ASCII letters move, so a
// non-ASCII byte cannot change which lines the two implementations keep.
func asciiLower(s string) string {
	lowered := []byte(s)
	for i, c := range lowered {
		if c >= 'A' && c <= 'Z' {
			lowered[i] = c + ('a' - 'A')
		}
	}
	return string(lowered)
}
