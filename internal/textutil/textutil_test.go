package textutil_test

import (
	"strings"
	"testing"

	"karma/internal/textutil"
)

func TestCStringReadsTheFieldAndTrimsBlanks(t *testing.T) {
	if got := textutil.CString([]byte("5.15.0-\x00xxxxxxx")); got != "5.15.0-" {
		t.Errorf("terminated field = %q", got)
	}
	if got := textutil.CString([]int8{'x', 0, 'y'}); got != "x" {
		t.Errorf("int8 field = %q", got)
	}
	if got := textutil.CString([]byte("no pad")); got != "no pad" {
		t.Errorf("unterminated field = %q", got)
	}
	if got := textutil.CString([]byte("padded ")); got != "padded" {
		t.Errorf("blank-padded field = %q", got)
	}
}

func TestCStrKeepsEveryByteBeforeTheTerminator(t *testing.T) {
	if got := textutil.CStr([]byte("root\x00rest")); got != "root" {
		t.Errorf("terminated = %q", got)
	}
	if got := textutil.CStr([]byte("root ")); got != "root " {
		t.Errorf("blank-padded record = %q", got)
	}
	if got := textutil.CStr([]byte("root")); got != "root" {
		t.Errorf("unterminated = %q", got)
	}
}

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

// Head is the line cap two tiers share: the streaming harvest's boundary (each
// kept line's own terminator, one line past the cap deciding) and `head -n`.
// The split is on \n alone, so a body of CR-separated output is one long line
// here even though Lines breaks it.
func TestHead(t *testing.T) {
	cases := []struct {
		in        string
		n         int
		want      string
		truncated bool
	}{
		{"a\nb\n", 2, "a\nb\n", false},
		{"a\nb", 2, "a\nb", false},
		{"a\nb\nc\n", 2, "a\nb\n", true},
		{"a\nb\nc", 2, "a\nb\n", true},
		{"", 2, "", false},
		{"\n", 1, "\n", false},
		{"a\nb\nc\n", 0, "a\nb\nc\n", false},
		{"a\rb\r", 1, "a\rb\r", false},
	}
	for _, tc := range cases {
		got, truncated := textutil.Head(tc.in, tc.n)
		if got != tc.want || truncated != tc.truncated {
			t.Errorf("Head(%q, %d) = %q, %v; want %q, %v", tc.in, tc.n, got, truncated, tc.want, tc.truncated)
		}
	}
}
