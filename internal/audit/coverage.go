package audit

// Coverage is one statement about how far the run's evidence reached: the
// area it speaks for, the state of the evidence there, and the sentence the
// report prints. The text renderer prints Detail; the JSON report and the
// dedup key carry the structure, so a machine can tell a degradation from a
// scope statement without parsing prose.

import "fmt"

// CoverageStatus grades one area's evidence state.
type CoverageStatus uint8

const (
	// CoverageComplete states the evidence the run gathered: the read or
	// comparison happened, and this is what it covered.
	CoverageComplete CoverageStatus = iota
	// CoverageDegraded names a limit: a truncated walk, an unreadable file,
	// a check the run skipped, a display that shows less than it judged. The
	// results still answer, with less behind them.
	CoverageDegraded
	// CoverageAbsent names a source the run never had: no package database,
	// no artifact boundary, a collector or judge that stopped.
	CoverageAbsent
)

var coverageStatusNames = [...]string{"complete", "degraded", "absent"}

func (s CoverageStatus) String() string {
	if int(s) >= len(coverageStatusNames) {
		return "complete"
	}
	return coverageStatusNames[s]
}

// MarshalText writes the status word the JSON report prints.
func (s CoverageStatus) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Coverage is one coverage record.
type Coverage struct {
	// Area names the stage or bounded domain the statement answers to: the
	// registry's module words, or boundary, catalog, collection, ledger,
	// startup and graph for the stages outside the registry.
	Area string `json:"area"`
	// Status is the evidence state in that area.
	Status CoverageStatus `json:"status"`
	// Count is the number of objects the statement covers, when it speaks
	// about a set; a scope statement leaves it zero.
	Count int `json:"count,omitempty"`
	// Detail is the report line, verbatim.
	Detail string `json:"detail"`
}

// coverageComplete states what the evidence covered: the read or comparison
// happened, and the sentence names its reach.
func coverageComplete(area, detail string) Coverage {
	return Coverage{Area: area, Status: CoverageComplete, Detail: detail}
}

// coverageGap names a limit in one area: the read happened, with less behind
// it than a whole run would gather.
func coverageGap(area, detail string) Coverage {
	return Coverage{Area: area, Status: CoverageDegraded, Detail: detail}
}

// coverageAbsent names a source the run never had.
func coverageAbsent(area, detail string) Coverage {
	return Coverage{Area: area, Status: CoverageAbsent, Detail: detail}
}

// coverageLines wraps plain lines one record each, at the package boundary:
// the startup corpus and the package catalog sit below the audit package and
// answer in plain lines.
func coverageLines(area string, status CoverageStatus, lines []string) []Coverage {
	if len(lines) == 0 {
		return nil
	}
	records := make([]Coverage, 0, len(lines))
	for _, line := range lines {
		records = append(records, Coverage{Area: area, Status: status, Detail: line})
	}
	return records
}

// collectionStopped is the one record an interrupted collection appends. The
// module loop, the post-loop ledger bail and the catalog stage all answer
// with it, so the dedup downstream has one statement to collapse.
func collectionStopped(err error) Coverage {
	return coverageAbsent("collection", "collection stopped: "+err.Error())
}

// shownMore trims a judged list to its display limit and answers the
// coverage record for the rest. The remainder counts only the rows this run
// judged, so a scoped run never reports rows another scope dropped. A list
// within the limit answers no notes.
func shownMore[T any](items []T, limit int, area, what string) ([]T, []Coverage) {
	if len(items) <= limit {
		return items, nil
	}
	return items[:limit], []Coverage{{
		Area:   area,
		Status: CoverageDegraded,
		Count:  len(items) - limit,
		Detail: fmt.Sprintf("%d more %s than the report shows", len(items)-limit, what),
	}}
}

// uniqueCoverage keeps the first record of each distinct statement. Records
// are comparable, so the dedup key is the whole record: two producers that
// state the same fact in the same words collapse to one line, and the same
// words about different areas stay apart.
func uniqueCoverage(records []Coverage) []Coverage {
	seen := make(map[Coverage]bool, len(records))
	out := records[:0]
	for _, record := range records {
		if seen[record] {
			continue
		}
		seen[record] = true
		out = append(out, record)
	}
	return out
}
