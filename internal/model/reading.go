// The reading layer's vocabulary: a body in, the sections and lines out.

package model

// LineMatch is a span stated by a normalizer: it falls on line Line of the
// body (0-based).
type LineMatch struct {
	Line  int
	Match Match
}

// Shaped is normalized body text plus the spans the normalizer stated up
// front. Records is the same body as fields — one record per line of Text — for
// a body that arrived encoded (see RecordSet); a normalizer of plain text
// leaves it nil.
type Shaped struct {
	Text    string
	Notes   []LineMatch
	Records *RecordSet
}

// Normalizer is a pure function over one section body: Probe.Adapt aligns the
// dialect of one tier, Check.Normalize normalizes the body. The first
// parameter is the section title (empty for the preamble section), and
// normalizers that must tell sources apart use it. Returning nil means the
// body is used as is.
type Normalizer func(title string, body string) *Shaped

// Transformer is a whole-body shaping step: a tier's raw output in, the body the
// reading pipeline splits into sections out. It is Probe.Assemble's type, for a
// tier whose output is a marked record stream rather than the body itself — the
// join runs once on the Go side for both sources instead of once per language
// on the target.
type Transformer func(text string) string

// Line is one line after folding and before filtering. Number is the line
// number in the whole text; filtered-out lines still consume a number.
// Record is the line as fields when the body arrived as records, which is what
// the check's form draws; a line of plain text has none.
type Line struct {
	Number   int
	Text     string
	Severity Severity
	Matches  []Match
	Record   *Record
}

// Section is one file or one preamble. An empty Title is the body before the
// first section marker. Columns are the section's record columns — the head its
// form draws — and are empty for a section of plain text.
type Section struct {
	Title        string
	TitleMatches []Match
	Lines        []Line
	Columns      []string
}

// Document is the reading result of one text. Filtered is a sequence of
// (filter id, hit count).
type Document struct {
	Sections  []Section
	Truncated bool
	Filtered  []FilterCount
}

// FilterCount is the number of lines one filter hid.
type FilterCount struct {
	ID    string
	Count int
}

// Body is what a collection read: the sections of the tier's answer, in the
// order the tier produced them. A body of one output is one untitled section.
type Body struct{ Sections []BodySection }

// BodySection is one part of a body: the title the report shows above it (empty
// for the untitled leading part) and the text or fields under it. Exactly one of
// Text and Records is set.
//
// The title is carried here rather than recognized in the text: a section
// boundary is the collection's own statement about what it read, so no byte of
// file content or tool output can become one. Titles is that statement one level
// down — the parts a tier prints inside one answer, still declared by the check
// rather than found in the bytes.
//
// Adapt is the producing tier's dialect alignment over this section (nil for
// none): a tier declares it once, and the reading runs it on every section that
// tier answered with, before the check's own normalization.
//
// Assemble is the producing tier's own join (nil for none): the section's text is
// a marked record stream rather than the body itself, and the join reduces it to
// rows before the reading sees them. The stream stays the evidence — what the
// target sent — while the rows are what is read and shown.
type BodySection struct {
	Title string
	// Titles are the section titles this one body carries inside it (nil for
	// none): the reading splits the text at each one and reads every part as its
	// own section. The join ran before the split, so a part never runs Assemble
	// again.
	Titles   []string
	Text     string
	Records  *RecordSet
	Adapt    Normalizer
	Assemble Transformer
}

// ReadRequest is one body's reading: the check the body belongs to (its rules,
// filters, scan budget and normalization), the body the winning step answered
// with, the run's severity floor, and whether the channel stopped the body at a
// row cap.
type ReadRequest struct {
	Check     *Check
	Body      Body
	Floor     SeverityFloor
	Truncated bool
}
