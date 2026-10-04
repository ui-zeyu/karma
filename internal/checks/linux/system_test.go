package linux

import (
	"testing"

	"karma/internal/model"
)

// ruleByID finds a rule by id across checks; the test fails if it is missing.
func ruleByID(t *testing.T, checks []*model.Check, id string) model.Rule {
	t.Helper()
	for _, check := range checks {
		for _, rule := range check.Rules {
			if rule.ID == id {
				return rule
			}
		}
	}
	t.Fatalf("rule %s not in catalog", id)
	return model.Rule{}
}

// A trailing empty component (trailing PATH colon) once slipped through: the
// lookahead rewrite dropped the `$` arm.
func TestEnvPathDot(t *testing.T) {
	rule := ruleByID(t, SystemChecks, "env-path-dot")
	cases := []struct {
		line string
		want bool
	}{
		{"PATH=/usr/local/bin:/usr/bin:/bin", false},
		{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", false},
		{"PATH=/usr/local/bin:/usr/bin:/bin:", true}, // trailing empty component
		{"PATH=:/usr/bin", true},                     // leading empty component
		{"PATH=/a::/b", true},                        // middle empty component
		{"PATH=/usr/bin:.", true},                    // trailing bare dot
		{"PATH=.:/usr/bin", true},                    // leading bare dot
		{"PATH=/a:.:/b", true},                       // middle bare dot
		{"PATH=", true},                              // empty PATH
		{"LD_LIBRARY_PATH=/x:/y", false},             // only PATH= is targeted
		{"PYTHONPATH=/usr/local/lib", false},
	}
	for _, c := range cases {
		if _, _, ok := rule.Find(c.line); ok != c.want {
			t.Errorf("env-path-dot on %q matched=%v, want %v", c.line, ok, c.want)
		}
	}
}
