package model

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// prefilterPatterns are the shapes the extractor reads: a leading \b or ^, an
// alternation of names (with and without a shared prefix), an optional or
// repeated group, a character class, a case-folded literal, an anchored tail,
// and nesting.
var prefilterPatterns = []string{
	`\bld\.so\.preload\b`,
	`-----BEGIN [A-Z0-9 ]*PRIVATE KEY`,
	`\(deleted\)`,
	`\b(?:curl|wget)\b[^|\n]*\|\s*(?:ba|da|z|k)?sh\b`,
	`\b(?:xmrig|kinsing|ddgs|masscan)\b`,
	`/?(?:(?:var/)?tmp|dev/shm)/\.[A-Za-z0-9_.-]+`,
	`\buser(?:add|mod|del)\b`,
	`(?i)\bwebshell\b`,
	`^/\S+`,
	`^[ \t\r]*$`,
	`\b(?:ba|z)?sh\s+-i\b`,
	`a(?:b|c)d`,
	`a?b`,
	`a*b`,
	`a{0,2}b`,
	`a{2,3}b`,
	`(a)(b)`,
	`(?:ab|cd|ef)`,
	`(?:ab|cd|ef)?x`,
	`^! `,
	`\d+`,
	`[a-z]+`,
	`.`,
	`.*`,
	`^$`,
	`(?:)`,
	`ab|a`,
	`(?:foo|foobar)baz`,
	`(?P<name>abc)`,
	`\b(?:[A-Za-z0-9.-]+/)*authorized_keys\d?\b`,
	`\.(?:php[3-5]?|phtml|jsp|jspx|sh|py)$`,
	`^(?:www-data|nginx)\s.*\b(?:sh|python[0-9.]*|nc)\b`,
	`>>{1,2}\s*\S*authorized_keys`,
	`(?:zfs|ext4)`,
	`\b(?:docker|libpod)[/.-]`,
	`[+=]`,
	`\bcap_[a-z_]+(?:[+=][a-z]*)?`,
}

// TestPrefilterIsNecessary pins the extractor's one obligation: a text the
// pattern matches contains one of the literals. Every candidate text over a
// small alphabet is tried, so a rewrite that drops an alternation branch or
// keeps a literal an optional group is not obliged to contain fails here.
func TestPrefilterIsNecessary(t *testing.T) {
	for _, source := range prefilterPatterns {
		pattern := regexp.MustCompile(source)
		literals := prefilter(source)
		for _, candidate := range candidateTexts([]string{"a", "b", "c", "d", "e", "f", "x", "/", "1", " ", "-"}, 4) {
			if pattern.FindStringIndex(candidate) == nil {
				continue
			}
			if !prefilterMatches(literals, candidate) {
				t.Fatalf("pattern %q matched %q, but the prefilter %q rejected it", source, candidate, literals)
			}
		}
	}
}

// TestPrefilterKeepsTheStrongShapes records which shapes earn a prefilter, so a
// change that quietly drops it for the expensive ones — the leading \b, the
// alternation, the character class — is visible. A pattern whose only provable
// literal is a single byte keeps its plain regex: the scan would cost as much
// as the engine call and filter almost nothing.
func TestPrefilterKeepsTheStrongShapes(t *testing.T) {
	cases := []struct {
		pattern  string
		literals []string
	}{
		{`\bld\.so\.preload\b`, []string{"ld.so.preload"}},
		{`\b(?:curl|wget)\b`, []string{"curl", "wget"}},
		{`-----BEGIN [A-Z0-9 ]*PRIVATE KEY`, []string{"-----BEGIN "}},
		{`(?:(?:var/)?tmp|dev/shm)/x`, []string{"dev/shm", "tmp"}},
		{`\b(?:xmrig|kinsing)\b`, []string{"kinsing", "xmrig"}},
		{`\bcap_[a-z_]+`, []string{"cap_"}},
		// The parser folds `\.(?:php|phtml)` into `\.ph(?:p|tml)`, so the
		// quoted literal is the whole four-byte tail of the first branch; the
		// shared prefix belongs to the concat that is scanned instead.
		{`\.(?:php|phtml)$`, []string{"tml", "p"}},
		// nothing to prove: a character class, a wildcard, a case-folded name,
		// an optional or repeated group, and a concat whose own classes leave
		// only one-byte literals behind
		{`\d+`, nil},
		{`^[ \t\r]*$`, nil},
		{`(?i)\bwebshell\b`, nil},
		{`a?b`, nil},
		{`.*`, nil},
		{`a(?:b|c)d`, nil},
		{`ab|a`, nil},
	}
	for _, c := range cases {
		got := prefilter(c.pattern)
		if strings.Join(got, ",") != strings.Join(c.literals, ",") {
			t.Errorf("prefilter(%q) = %q, want %q", c.pattern, got, c.literals)
		}
	}
}

// TestPrefilterOnAMatchingLine is the end-to-end face of the same rule: the
// spans a rule reports are unchanged by the prefilter, on a line that matches
// and on one that does not.
func TestPrefilterOnAMatchingLine(t *testing.T) {
	rule := NewRule("test", `\b(?:curl|wget)\b[^|\n]*\|\s*(?:ba|da|z|k)?sh\b`, Critical, "piped to a shell")
	line := "curl -s http://example.test/x.sh | sh"
	start, end, ok := rule.Find(line)
	if !ok || line[start:end] == "" {
		t.Fatalf("the prefilter rejected a matching line: %q", line)
	}
	if _, _, ok := rule.Find("-rw-r--r-- 1 root root 10 Mar 15 10:20 keep.log"); ok {
		t.Fatal("a line with no candidate literal should not match")
	}
}

// FuzzRulePrefilter is the differential check on the same obligation with
// patterns the tables above never thought of: whatever the engine finds, the
// prefiltered Find must find as well. A literal the analysis wrongly requires
// shows up here as a missed span.
func FuzzRulePrefilter(f *testing.F) {
	for _, source := range prefilterPatterns {
		f.Add(source, "curl -s http://example.test/x.sh | sh")
	}
	f.Fuzz(func(t *testing.T, source, line string) {
		compiled, err := regexp.Compile(source)
		if err != nil {
			t.Skip()
		}
		rule := Rule{
			ID: "fuzz", Pattern: compiled, Severity: Critical, Message: "fuzz",
			literals: prefilter(source),
		}
		gotStart, gotEnd, gotOK := rule.Find(line)
		wantStart, wantEnd, wantOK := findWithoutPrefilter(rule, line)
		if gotStart != wantStart || gotEnd != wantEnd || gotOK != wantOK {
			t.Fatalf("prefilter changed the verdict for %q on %q: got (%d,%d,%v), want (%d,%d,%v)",
				source, line, gotStart, gotEnd, gotOK, wantStart, wantEnd, wantOK)
		}
	})
}

// findWithoutPrefilter is Rule.Find with the prefilter left out: the reference
// the fuzz compares against.
func findWithoutPrefilter(r Rule, line string) (int, int, bool) {
	loc := r.Pattern.FindStringIndex(line)
	if loc == nil || (r.Exclude != nil && r.Exclude.MatchString(line)) {
		return 0, 0, false
	}
	return loc[0], loc[1], true
}

// candidateTexts is every string over the alphabet up to maxLen, joined — a
// small enough space to walk exhaustively and wide enough to exercise the
// extractor's branches.
func candidateTexts(alphabet []string, maxLen int) []string {
	texts := []string{""}
	current := []string{""}
	for length := 1; length <= maxLen; length++ {
		var next []string
		for _, prefix := range current {
			for _, letter := range alphabet {
				next = append(next, prefix+letter)
			}
		}
		texts = append(texts, next...)
		current = next
	}
	if len(texts) < 1000 {
		panic(fmt.Sprintf("candidate space too small: %d", len(texts)))
	}
	return texts
}
