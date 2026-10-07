// Forms: how one kind of body is drawn.
//
// A check declares the shape of its output — a table, a column of ls -l rows, a
// tree, prose — and the form lays that shape out at the terminal's width. The
// hits it paints were located by the rules that judged the records (see
// Matcher), so a rule reads the same in a table and in prose and the form never
// has to infer which cell a byte range was meant for.

package model

// Form is the shape one check's body is drawn in. Implementations live in
// internal/form; a check without one is read and drawn as lines of text.
//
// A form does not decide where a hit goes: the rule that judged the record
// already said which field it fell in (see Matcher), so the form only paints.
type Form interface {
	// Render lays out one section's records at the given width, with the
	// caller's structural rows (a counted gap) interleaved where they fall.
	Render(block Block, opts RenderOptions) []string
}

// Block is one section's worth of records as the presentation reads it: the
// column names from the record set, and the items in display order.
type Block struct {
	Header []string
	Items  []BlockItem
}

// BlockItem is one row of a block: a record to draw, the hits the reading
// layer judged on it (each hit says its own reason, where the form puts it),
// or a structural note the caller inserted where the display budget hid rows.
type BlockItem struct {
	Rec     *Record
	Matches []Match
	Note    string
}

// RenderOptions is what the form may not decide for itself: the text width it
// has to fit (the panel's inner width, so nothing reaches the terminal's last
// column) and whether the stream is a terminal at all. Color off means the same
// layout with no escapes, which is what a redirected report prints.
type RenderOptions struct {
	Width int
	Color bool
}
