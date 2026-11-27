package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCoverageStatusWords(t *testing.T) {
	if CoverageComplete.String() != "complete" || CoverageDegraded.String() != "degraded" ||
		CoverageAbsent.String() != "absent" {
		t.Errorf("status words = %s %s %s", CoverageComplete, CoverageDegraded, CoverageAbsent)
	}
	data, err := json.Marshal(Coverage{Area: "ledger", Status: CoverageAbsent, Detail: "x"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(data), `"status":"absent"`) {
		t.Errorf("json = %s, want the status word", data)
	}
}

func TestShownMoreCarriesTheRecord(t *testing.T) {
	items := []string{"a", "b", "c"}
	shown, notes := shownMore(items, 2, "web", "web script(s)")
	if len(shown) != 2 || len(notes) != 1 || notes[0].Count != 1 || notes[0].Area != "web" ||
		notes[0].Status != CoverageDegraded || notes[0].Detail != "1 more web script(s) than the report shows" {
		t.Errorf("shownMore = %v %+v", shown, notes)
	}
	if _, notes := shownMore(items, 3, "web", "web script(s)"); len(notes) != 0 {
		t.Errorf("within-limit notes = %+v, want quiet", notes)
	}
}

func TestUniqueCoverageKeepsFirstRecord(t *testing.T) {
	records := []Coverage{
		coverageGap("collection", "collection stopped: context canceled"),
		{Area: "ledger", Status: CoverageDegraded, Detail: "same words"},
		{Area: "kernel", Status: CoverageDegraded, Detail: "same words"},
		coverageGap("collection", "collection stopped: context canceled"),
	}
	unique := uniqueCoverage(records)
	if len(unique) != 3 {
		t.Errorf("uniqueCoverage = %v, want the duplicate collapsed and the areas kept apart", unique)
	}
}
