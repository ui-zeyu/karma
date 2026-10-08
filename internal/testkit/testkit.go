// Package testkit holds the test-only helpers shared across packages: check
// lookup, and reading a sample body the way a report would.
//
// A sample has no tier, so nothing states a dialect for it: the reading runs
// the check's own normalization and no alignment, and the floor is FloorAll —
// the tests that care about a floor state it on the request themselves.
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

// Analyze reads one sample text the way the report would: one untitled section,
// the check's own rules, filters and normalization.
func Analyze(text string, check *model.Check) model.Document {
	return reader.Read(model.ReadRequest{
		Check: check,
		Body:  model.Body{Sections: []model.BodySection{{Text: text}}},
		Floor: model.FloorAll,
	})
}

// RecordsDocument reads one sample record set the way the report would: a body
// that arrived as fields, in one untitled section.
func RecordsDocument(set *model.RecordSet, check *model.Check) model.Document {
	return reader.Read(model.ReadRequest{
		Check: check,
		Body:  model.Body{Sections: []model.BodySection{{Records: set}}},
		Floor: model.FloorAll,
	})
}

// HitIDs reads one sample text the way the report would and returns the rule ids it lights.
func HitIDs(t *testing.T, text string, check *model.Check) []string {
	t.Helper()
	document := Analyze(text, check)
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
