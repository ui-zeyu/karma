package panel

// Wrapping is where painted rows meet the panel's width: a row too wide for the
// rail must keep the color of every cell on both sides of the break.

import (
	"strings"
	"testing"
)

func TestWrapKeepsCellPaintAcrossTheBreak(t *testing.T) {
	row := Paint(true, Fg(203), "0123456789") + "  " + Paint(true, Fg(2), "abcdef")
	lines := Wrap(row, 8)
	if len(lines) != 3 {
		t.Fatalf("wrapped into %d lines, want 3: %q", len(lines), lines)
	}
	for index, line := range lines {
		if width := DisplayWidth(line); width > 8 {
			t.Errorf("line %d is %d columns wide: %q", index, width, line)
		}
		if strings.Contains(line, "\x1b[38;5;") && !strings.HasSuffix(line, Reset) {
			t.Errorf("line %d leaves its paint open: %q", index, line)
		}
	}
	if !strings.HasPrefix(lines[0], Fg(203)) {
		t.Errorf("the first line lost the cell hue: %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], Fg(203)) {
		t.Errorf("the continuation line did not re-open the cell hue: %q", lines[1])
	}
	if !strings.Contains(lines[1], Fg(2)) {
		t.Errorf("the second cell lost its hue: %q", lines[1])
	}
	if !strings.HasPrefix(lines[2], Fg(2)) {
		t.Errorf("the second cell's continuation lost its hue: %q", lines[2])
	}
}

func TestWrapKeepsAWholeLinePaintAcrossWords(t *testing.T) {
	lines := Wrap(Paint(true, Fg(MutedColor), "one two three four"), 9)
	if len(lines) < 3 {
		t.Fatalf("wrapped into %d lines, want at least 3: %q", len(lines), lines)
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, Fg(MutedColor)) || !strings.HasSuffix(line, Reset) {
			t.Errorf("a wrapped prose line lost its paint: %q", line)
		}
		if width := DisplayWidth(line); width > 9 {
			t.Errorf("line is %d columns wide: %q", width, line)
		}
	}
}

func TestWrapLeavesAShortLineAlone(t *testing.T) {
	line := Paint(true, Fg(2), "active")
	if lines := Wrap(line, 20); len(lines) != 1 || lines[0] != line {
		t.Errorf("a short painted line was rewritten: %q", lines)
	}
}
