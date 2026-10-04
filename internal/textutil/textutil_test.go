package textutil_test

import (
	"strings"
	"testing"

	"karma/internal/textutil"
)

func TestLinesMatchesSplitlines(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"a", "a"},
		{"a\n", "a"},
		{"a\n\n", "a|"},
		{"\n", ""},
		{"\n\n", "|"},
		{"a\r\nb\r\n", "a|b"},
		{"a\rb", "a|b"},
		{"keep me\nhide this\n", "keep me|hide this"},
	}
	for _, tc := range cases {
		got := strings.Join(textutil.CollectLines(tc.in), "|")
		if got != tc.want {
			t.Errorf("%q -> %q, want %q", tc.in, got, tc.want)
		}
	}
}
