// Skeleton styling for help and error output. The evidence surfaces have their
// own color language in the render package; the command-line skeleton reuses
// the same accents — bold section headers and names, muted descriptions, a red
// error line, yellow suggestions — under the same rule: no color when the
// stream is not a terminal. Detection is per stream, so a capture buffer (as in
// every test) or a pipe renders plain text.

package cli

import (
	"io"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"karma/internal/render"
)

// streamStyles colors one output stream; on the plain profile every style
// passes its text through unchanged.
type streamStyles struct {
	bold  func(string) string
	muted func(string) string
	err   func(string) string
	hint  func(string) string
}

// stylesFor detects the stream's color profile (honoring NO_COLOR via termenv's
// environment handling) and binds the styles to it.
func stylesFor(w io.Writer) streamStyles {
	return stylesForProfile(w, termenv.NewOutput(w).EnvColorProfile())
}

// stylesForProfile builds the styles at a fixed profile; tests use it to force
// color on a capture buffer. The hues come from the report's palette, so the
// skeleton and the evidence read the same.
func stylesForProfile(w io.Writer, profile termenv.Profile) streamStyles {
	out := termenv.NewOutput(w, termenv.WithProfile(profile))
	foreground := func(color lipgloss.Color) func(string) string {
		return func(s string) string { return out.String(s).Foreground(out.Color(string(color))).String() }
	}
	return streamStyles{
		bold:  func(s string) string { return out.String(s).Bold().String() },
		muted: foreground(render.MutedColor),
		err:   foreground(render.ErrorColor),
		hint:  foreground(render.HintColor),
	}
}
