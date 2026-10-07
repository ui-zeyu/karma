package linux

import (
	"testing"

	"karma/internal/model"
)

// ruleByID finds a pattern rule by id across checks; the test fails if it is
// missing. The tests here are about the patterns themselves, so they ask for
// that implementation of a Matcher by name.
func ruleByID(t *testing.T, checks []*model.Check, id string) model.Rule {
	t.Helper()
	for _, check := range checks {
		for _, rule := range check.Rules {
			if rule.Name() != id {
				continue
			}
			pattern, ok := rule.(model.Rule)
			if !ok {
				t.Fatalf("rule %s is not a pattern rule (%T)", id, rule)
			}
			return pattern
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
		{"LD_LIBRARY_PATH=/x::/y", false}, // another variable's empty component is not PATH
		{"MANPATH=/usr/share/man::/opt/man", false},
		{"SOMEVAR=a::b", false},
		{"PATH=/usr/bin:/bin/", false}, // a trailing slash is not an empty component
	}
	for _, c := range cases {
		rec := model.TextRecord(c.line)
		if got := rule.Judge(&rec) != nil; got != c.want {
			t.Errorf("env-path-dot on %q matched=%v, want %v", c.line, got, c.want)
		}
	}
}
