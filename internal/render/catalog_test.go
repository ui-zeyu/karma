package render

import (
	"testing"

	"karma/internal/checks"
	"karma/internal/model"
)

// Every syntax the catalog declares has a lexer. A name that is not in the
// model.Syntax vocabulary reaches the catalog only as a raw literal — the
// constants make the other misspellings compile errors, and a misnamed constant
// is one too — and the lexer table answers nil for it, which would leave that
// check's panel silently without its color.
func TestCatalogSyntaxIsALexer(t *testing.T) {
	declared := func(check *model.Check, syntax model.Syntax, where string) {
		if syntax != "" && buildLineStyler(syntax) == nil {
			t.Errorf("%s declares %s syntax %q, which has no lexer", check.ID, where, syntax)
		}
	}
	for _, check := range checks.AllChecks() {
		declared(check, check.Syntax, "body")
		for _, override := range check.SectionSyntax {
			declared(check, override.Syntax, "section "+override.Title)
		}
	}
}
