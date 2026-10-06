// Package testkit holds the test-only helpers shared across packages: check
// lookup and rule-hit extraction for the catalog tests.
package testkit

import (
	"testing"

	"karma/internal/model"
	"karma/internal/reader"
)

// CheckByID finds a check by id across the catalog; the test fails if it is missing.
func CheckByID(t *testing.T, catalog []*model.Check, id string) *model.Check {
	t.Helper()
	for _, check := range catalog {
		if check.ID == id {
			return check
		}
	}
	t.Fatalf("check %s not in catalog", id)
	return nil
}

// HitIDs reads one sample text the way the report would and returns the rule ids it lights.
func HitIDs(t *testing.T, text string, check *model.Check) []string {
	t.Helper()
	document := reader.Analyze(text, check.Rules, check.Filters, check.Normalize, 0, model.FloorAll)
	var ids []string
	for _, section := range document.Sections {
		for _, match := range section.TitleMatches {
			ids = append(ids, match.ID)
		}
		for _, line := range section.Lines {
			for _, match := range line.Matches {
				ids = append(ids, match.ID)
			}
		}
	}
	return ids
}
