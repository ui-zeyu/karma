package reader

import (
	"strings"
	"testing"
	"unicode/utf8"

	"karma/internal/model"
)

func FuzzCapBytes(f *testing.F) {
	f.Add("hello, 世界", 5)
	f.Add("", 0)
	f.Add(string([]byte{0xff, 0xfe}), 1)
	f.Fuzz(func(t *testing.T, text string, limit int) {
		got, truncated := capBytes(text, limit)
		// valid input must stay valid: the cut backs off to a rune boundary.
		// Invalid bytes pass through untouched — sanitizing lives in harvest.
		if utf8.ValidString(text) && !utf8.ValidString(got) {
			t.Fatalf("capBytes turned valid input into invalid UTF-8")
		}
		effective := limit
		if effective <= 0 {
			effective = MaxScanBytes
		}
		if len(got) > effective {
			t.Fatalf("result of %d bytes exceeds the cap of %d", len(got), effective)
		}
		if truncated != (len(text) > effective) {
			t.Fatalf("truncated = %v for %d input bytes at cap %d", truncated, len(text), effective)
		}
		if truncated && !strings.HasPrefix(text, got) {
			t.Fatalf("a capped result must be a prefix of the input")
		}
	})
}

// shout is a trivial shaper: it round-trips the body so the fuzz exercises the
// normalize path, including its notes bookkeeping.
func shout(_ string, body string) *model.Shaped {
	return &model.Shaped{Text: strings.ToUpper(body)}
}

func FuzzAnalyze(f *testing.F) {
	rules := []model.Matcher{
		model.NewRule("root-line", `root`, model.High, "root line"),
		model.NewRule("deleted-binary", `\(deleted\)`, model.Critical, "deleted"),
	}
	filters := []model.LineFilter{model.NewFilter("blank", `^[ \t]*$`, model.FilterDrop)}
	f.Add("== /etc/passwd\nroot:x:0:0:root:/root:/bin/sh\n\nplain\n", 0)
	f.Add("garbage\n", 100)
	f.Add("== a\n== b\ndeleted\n", -1)
	f.Fuzz(func(t *testing.T, text string, scanBytes int) {
		for _, normalize := range []model.Normalizer{nil, shout} {
			doc := Analyze(text, rules, filters, scanBytes, model.FloorAll, normalize)
			for _, section := range doc.Sections {
				// a section survives with an empty body only when its title matched a rule
				if len(section.Lines) == 0 && len(section.TitleMatches) == 0 {
					t.Fatalf("a kept section must carry a line or a matched title: %q", section.Title)
				}
				for _, line := range section.Lines {
					if line.Severity < model.Critical || line.Severity > model.Benign {
						t.Fatalf("severity out of range: %v", line.Severity)
					}
				}
			}
		}
	})
}
