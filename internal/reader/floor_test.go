// The severity floor is the run's own filter: a row below it is counted like a
// filtered line and left out of the document, whatever the check's own filters
// would have done with it. It filters the reading alone — the collection's raw
// text is what the reading read — so the floor never costs evidence.

package reader_test

import (
	"testing"

	"karma/internal/model"
	"karma/internal/reader"
)

// floor reads one body at a given floor: the pairs are (title, text), as the
// collection states them.
func floor(rules []model.Matcher, filters []model.LineFilter, at model.SeverityFloor, parts ...string) model.Document {
	body := model.Body{}
	for index := 0; index+1 < len(parts); index += 2 {
		body.Sections = append(body.Sections, model.BodySection{Title: parts[index], Text: parts[index+1]})
	}
	check := &model.Check{Rules: rules, Filters: filters}
	return reader.Read(model.ReadRequest{Check: check, Body: body, Floor: at})
}

// hiddenBelow is the count the floor hides, from the document's own counter.
func hiddenBelow(document model.Document) int {
	for _, count := range document.Filtered {
		if count.ID == "below-severity" {
			return count.Count
		}
	}
	return 0
}

// keptText is every line the document kept, in order.
func keptText(document model.Document) []string {
	var lines []string
	for _, section := range document.Sections {
		for _, line := range section.Lines {
			lines = append(lines, line.Text)
		}
	}
	return lines
}

func TestSeverityFloorKeepsOnlyTheLevelsAbove(t *testing.T) {
	parts := []string{"body", "high hit\nquiet row\n"}
	rules := []model.Matcher{rule("high", `^high`, model.High)}
	cases := []struct {
		name   string
		at     model.SeverityFloor
		kept   []string
		hidden int
	}{
		{"no floor keeps every row", model.FloorAll, []string{"high hit", "quiet row"}, 0},
		{"a finding floor keeps only the hit", model.FloorAbove(model.Low),
			[]string{"high hit"}, 1},
		{"a high floor keeps it", model.FloorAbove(model.High), []string{"high hit"}, 1},
		{"a critical floor drops it", model.FloorAbove(model.Critical),
			nil, 2},
		{"the quietest floor keeps every row", model.FloorAbove(model.Benign),
			[]string{"high hit", "quiet row"}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			document := floor(rules, nil, tc.at, parts...)
			if got := keptText(document); len(got) != len(tc.kept) {
				t.Fatalf("kept %q, want %q", got, tc.kept)
			}
			for index, want := range tc.kept {
				if got := keptText(document)[index]; got != want {
					t.Fatalf("row %d is %q, want %q", index, got, want)
				}
			}
			if got := hiddenBelow(document); got != tc.hidden {
				t.Fatalf("the floor counted %d hidden rows, want %d", got, tc.hidden)
			}
		})
	}
}

// The floor is judged before the filters and outranks them both ways: a keep
// filter does not rescue a row below it, and a drop filter does not hide a row
// above it.
func TestSeverityFloorOutranksTheChecksOwnFilters(t *testing.T) {
	parts := []string{"body", "low hit\nquiet row\n"}
	rules := []model.Matcher{rule("low", `^low`, model.Low)}

	kept := floor(rules, []model.LineFilter{keep(`^quiet`)}, model.FloorAbove(model.Medium), parts...)
	if got := keptText(kept); len(got) != 0 {
		t.Fatalf("a keep filter must not rescue a row below the floor: %q", got)
	}

	dropped := floor(rules, []model.LineFilter{drop(`^low`)}, model.FloorAbove(model.Low), parts...)
	if got := keptText(dropped); len(got) != 1 || got[0] != "low hit" {
		t.Fatalf("the floor keeps the finding the drop filter would hide: %q", got)
	}
}

// A section whose every row is below the floor carries no information: it goes
// the way of a section the filters emptied, so the check stays silent.
func TestSeverityFloorDropsAnEmptiedSection(t *testing.T) {
	document := floor(nil, nil, model.FloorAbove(model.Low),
		"/etc", "quiet row\n", "/tmp", "quiet row\n")
	if len(document.Sections) != 0 {
		t.Fatalf("every section was below the floor: %+v", document.Sections)
	}
	if got := hiddenBelow(document); got != 2 {
		t.Fatalf("both rows should be counted: %d", got)
	}
}

// A section title is structure, not a row: the floor leaves it alone even when
// the title itself matched a rule below it.
func TestSeverityFloorKeepsSectionTitles(t *testing.T) {
	rules := []model.Matcher{rule("hidden", `^/tmp/\.`, model.Low), rule("low", `^low`, model.Low)}
	document := floor(rules, nil, model.FloorAbove(model.High), "/tmp/.hidden", "low hit\n")
	if len(document.Sections) != 1 {
		t.Fatalf("the title keeps its section: %+v", document.Sections)
	}
	if got := len(document.Sections[0].TitleMatches); got != 1 {
		t.Fatalf("the title keeps its match: %d", got)
	}
	if got := len(document.Sections[0].Lines); got != 0 {
		t.Fatalf("the row is below the floor: %d", got)
	}
}
