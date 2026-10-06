// Package cluster does mtime clustering: parse the find metadata stream, break
// clusters at silences, and grade outlier lines on the spot. mtime-hunt and the
// directory listing checks (key-dirs, tmp-listing, pam, etc.) share the same
// thresholds and verdict semantics: a file time-isolated from the main cluster is
// an outlier, and an mtime in the future or over a day before ctime is the
// forged-timestamp case (where touch-forged old timestamps show up). OutlierMatch
// grades both from the parsed path, and the verdict surfaces as the line's color
// plus its ⟨reason⟩ annotation; the text itself carries no prefix. The collection
// rows are built in internal/script; this only consumes the retrieved text.
package cluster

import (
	"cmp"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/samber/lo"

	"karma/internal/model"
	"karma/internal/script"
	"karma/internal/textutil"
)

const (
	minQuiet    = 60.0    // lower bound of the silence boundary: pauses within a minute count as the same batch of activity
	separation  = 2.0     // the silent tier must be at least this multiple of the longest active gap; otherwise it's the same cadence
	spanShare   = 50.0    // denominator of the ratio floor: a gap must reach a fiftieth of the full span to be a silence candidate
	floorQuiet  = 86400.0 // absolute floor of the ratio floor: pauses within a day go to the distribution method
	massMedian  = 1.0     // mass-band threshold: the ratio floor is enabled only when the median gap is under one second
	futureSlack = 300.0   // allowed clock skew between target and local; only beyond this counts as a future time
	forgedGap   = 86400.0 // mtime earlier than ctime by more than this is a forgery sign; used only to upgrade outlier lines
)

var (
	scriptSuffix = regexp.MustCompile(`\.(?:php[3-5]?|phtml|jsp|jspx|asp|aspx|py|sh|pl|rb)$`)
	hiddenName   = regexp.MustCompile(`/\.[^/]+$`)
)

// OutlierMatch is the verdict for an outlier line: severity and reason are fixed at
// cluster time from the parsed path. marker is the internal verdict code from
// OutlierMarker; span is the displayed line length, and the range covers the whole
// line (a flagged line is colored entirely by severity and carries the ⟨reason⟩
// annotation).
func OutlierMatch(path, marker string, span int) *model.Match {
	verdict := func(id string, severity model.Severity, message string) *model.Match {
		return &model.Match{ID: id, Severity: severity, Message: message, Start: 0, End: span}
	}
	switch {
	case marker == "!!":
		return verdict("mtime-stamp-anomaly", model.High,
			"mtime in the future or over a day before ctime (timestamp likely forged)")
	case marker != "!":
		return nil
	case hiddenName.MatchString(path):
		return verdict("mtime-outlier-hidden", model.Medium, "hidden file with outlier mtime")
	case scriptSuffix.MatchString(path):
		return verdict("mtime-outlier-script", model.Low, "script with outlier mtime (webshell hunting)")
	default:
		return verdict("mtime-outlier", model.Low, "mtime isolated from the main cluster (outlier)")
	}
}

// OutlierMarker is the internal verdict code a collection row's marker prefix
// carries. It is never printed: the verdict shows as the line's severity color
// and its ⟨reason⟩ annotation.
func OutlierMarker(mtime, ctime float64, outlier bool, now time.Time) string {
	future := mtime > float64(now.Unix())+futureSlack
	forged := outlier && ctime-mtime > forgedGap
	switch {
	case future || forged:
		return "!!"
	case outlier:
		return "!"
	}
	return ""
}

// OutlierSizeLimit is the size cap for an outlier cluster: at most two files, or one percent of the whole.
func OutlierSizeLimit(total int) int {
	return max(2, total/100)
}

// MinorClusters returns all items of the sparse small clusters (groups no larger than limit), i.e. the outlier candidates.
func MinorClusters[T comparable](groups [][]T, limit int) map[T]bool {
	small := lo.Filter(groups, func(group []T, _ int) bool { return len(group) <= limit })
	return lo.SliceToMap(lo.FlatMap(small, func(group []T, _ int) []T { return group }),
		func(item T) (T, bool) { return item, true })
}

// ClusterByMtime scans once in ascending mtime order, breaking into clusters at
// silence boundaries layer by layer. The threshold is not fixed: an Otsu split on the
// gap distribution finds the natural boundary between "intra-activity gaps" and
// "silence"; after cutting, each segment recursively finds its own silence until the
// cadence within a segment is uniform, so multi-scale spans (hour-level and year-level
// silences coexisting) can be cut layer by layer. The mtime and path accessors are
// given by the caller; ties are ordered by path.
func ClusterByMtime[T any](files []T, mtime func(T) float64, path func(T) string) [][]T {
	ordered := slices.Clone(files)
	slices.SortStableFunc(ordered, func(a, b T) int {
		return cmp.Or(cmp.Compare(mtime(a), mtime(b)), cmp.Compare(path(a), path(b)))
	})
	return splitBySilence(ordered, mtime)
}

func splitBySilence[T any](ordered []T, mtime func(T) float64) [][]T {
	threshold, ok := quietThreshold(ordered, mtime)
	if !ok || len(ordered) < 2 {
		return [][]T{ordered}
	}
	groups := chunkAtSilence(ordered, mtime, threshold)
	return lo.FlatMap(groups, func(group []T, _ int) [][]T { return splitBySilence(group, mtime) })
}

// chunkAtSilence cuts the ordered sequence into segments at silence boundaries: break when an adjacent gap reaches the threshold.
func chunkAtSilence[T any](ordered []T, mtime func(T) float64, threshold float64) [][]T {
	var groups [][]T
	current := []T{ordered[0]}
	for _, item := range ordered[1:] {
		if mtime(item)-mtime(current[len(current)-1]) >= threshold {
			groups = append(groups, current)
			current = nil
		}
		current = append(current, item)
	}
	return append(groups, current)
}

// quietThreshold is the silence boundary between adjacent gaps; returns false when no
// trustworthy boundary is found (the whole span is one cluster).
//
// Two criteria, the ratio floor takes priority, the distribution boundary refines it
// within recursive layers:
//   - ratio floor: enabled when the median gap is under one second (the vast majority
//     of writes are one batch, the histogram is drowned by the mass band, isolated
//     large gaps carry no weight in the variance and the distribution method goes
//     blind): a gap reaching a fiftieth of the full span and no less than a day counts
//     as two batches of activity. The span is measured over the middle 98% of files,
//     so the leading/trailing one-percent outliers (including future timestamps) do
//     not participate, lest they inflate the floor and blunt it into never cutting;
//   - Otsu distribution boundary: take log2 of the positive gaps and do an Otsu split,
//     dividing gaps into the active tier and the silent tier; the silent tier must be
//     at least twice the longest active gap and no less than a minute to count as a
//     boundary, which short-span (half an hour to a few hours) silences rely on. When
//     a simultaneous burst leaves only one gap, it is judged alone against the silence
//     floor.
func quietThreshold[T any](ordered []T, mtime func(T) float64) (float64, bool) {
	gaps := positiveGaps(ordered, mtime)
	if len(gaps) == 0 {
		return 0, false
	}
	slices.Sort(gaps)
	if len(gaps) == 1 {
		return gaps[0], gaps[0] >= minQuiet
	}

	// ratio floor: when the mass band drowns the histogram, a big enough gap is silence
	last := len(ordered) - 1
	span := mtime(ordered[last*99/100]) - mtime(ordered[last/100])
	if gaps[len(gaps)/2] < massMedian {
		if candidate, ok := lo.Find(gaps, func(gap float64) bool { return gap >= max(floorQuiet, span/spanShare) }); ok {
			return candidate, true
		}
	}

	// Otsu split: find the cut point with maximum between-class variance in log2 space
	return otsuSplit(gaps)
}

// positiveGaps are the positive gaps among adjacent time differences.
func positiveGaps[T any](ordered []T, mtime func(T) float64) []float64 {
	gaps := make([]float64, 0, len(ordered)-1)
	for i := 1; i < len(ordered); i++ {
		if gap := mtime(ordered[i]) - mtime(ordered[i-1]); gap > 0 {
			gaps = append(gaps, gap)
		}
	}
	return gaps
}

// otsuSplit does an Otsu split on log2 gaps: the silent tier must be at least twice the
// longest active gap and no less than a minute to count as a boundary. Prefix-sum
// progression: each step does only an O(1) mean difference.
func otsuSplit(gaps []float64) (float64, bool) {
	logs := lo.Map(gaps, func(gap float64, _ int) float64 { return math.Log2(gap) })
	total := lo.Sum(logs)
	bestScore, bestIndex := 0.0, 0
	left := 0.0
	for i := 1; i < len(gaps); i++ {
		left += logs[i-1]
		right := total - left
		diff := right/float64(len(gaps)-i) - left/float64(i)
		if score := float64(i) * float64(len(gaps)-i) * diff * diff; score > bestScore {
			bestScore, bestIndex = score, i
		}
	}
	if bestIndex == 0 {
		return 0, false
	}
	activeMax, quietMin := gaps[bestIndex-1], gaps[bestIndex]
	if quietMin >= minQuiet && quietMin >= separation*activeMax {
		return quietMin, true
	}
	return 0, false
}

// FindRow is one find metadata row. Date and clock keep the target's local convention; clustering uses epoch.
type FindRow struct {
	Mtime  float64
	Ctime  float64
	Stamp  string
	Date   string
	Nbytes int
	Path   string
}

// ParseFindRow parses one collection row: mtime, ctime, date, clock (%TS with a
// nanosecond fraction; only whole seconds are kept for display), bytes, path,
// tab-separated. Returns nil on a bad shape.
func ParseFindRow(line string) *FindRow {
	parts := strings.SplitN(line, "\t", 6)
	if len(parts) != 6 {
		return nil
	}
	mtime, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return nil
	}
	ctime, err := strconv.ParseFloat(parts[1], 64)
	if err != nil {
		return nil
	}
	nbytes, err := strconv.Atoi(parts[4])
	if err != nil {
		return nil
	}
	stamp, date, clock := parts[2], parts[2], parts[3]
	if i := strings.IndexByte(clock, '.'); i >= 0 {
		clock = clock[:i]
	}
	return &FindRow{
		Mtime:  mtime,
		Ctime:  ctime,
		Stamp:  stamp + " " + clock,
		Date:   date,
		Nbytes: nbytes,
		Path:   parts[5],
	}
}

// Entry is one directory listing row: mtime/ctime lead (tab-separated), the body is an ls -l row shape.
type Entry struct {
	Mtime float64
	Ctime float64
	Row   string
}

// ParseEntry parses one collection row; returns nil on a bad shape.
func ParseEntry(line string) *Entry {
	parts := strings.SplitN(line, "\t", 3)
	if len(parts) != 3 {
		return nil
	}
	mtime, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return nil
	}
	ctime, err := strconv.ParseFloat(parts[1], 64)
	if err != nil {
		return nil
	}
	return &Entry{Mtime: mtime, Ctime: ctime, Row: parts[2]}
}

// EntryPath returns the path of one listing row: the row shape is
// %M %n %u %g %s %Tb %Td %TH:%TM followed by the path, which is used for tie
// ordering. A row that does not carry those columns is returned whole.
func EntryPath(e *Entry) string {
	if fields, ok := script.SplitLsBody(e.Row); ok {
		return fields[script.LsBodyPath]
	}
	return e.Row
}

// The union of collection rows and non-collection rows (descriptions, blank lines) in a section body.
type row struct {
	entry *Entry // nil means a non-collection row, passed through as-is
	text  string
}

// ListingNormalize shapes a directory listing section (key-dirs/unit-dirs etc.):
// cluster and grade outliers, strip the collection prefix, and line the rows up
// into ls -l columns. The title parameter comes from the reading layer's section
// split; clustering looks only at body lines. The thresholds and verdicts are
// mtime-hunt's, laid down as ranges on the spot at cluster time (OutlierMatch). A
// section with sparse small clusters and no dominant main cluster is the
// environment's daily write cadence; flagging everything would only flood the
// screen, so it stays quiet; non-collection rows pass through as-is.
//
// Columns are lined up here, on the whole section, so what the panel shows is
// what the SSH channel's find rows and the local channel's own rows both become;
// spans are stated over the aligned text, which is the text the reader sees.
func ListingNormalize(now func() time.Time) model.Normalizer {
	return func(_ string, text string) *model.Shaped {
		rows := lo.Map(textutil.CollectLines(text), func(line string, _ int) row {
			return row{entry: ParseEntry(line), text: line}
		})
		entries := lo.FilterMap(rows, func(r row, _ int) (*Entry, bool) { return r.entry, r.entry != nil })
		if len(entries) == 0 {
			return nil
		}
		moment := now()

		groups := ClusterByMtime(entries, entryMtime, EntryPath)
		limit := OutlierSizeLimit(len(entries))
		mainMass := lo.SumBy(lo.Filter(groups, func(group []*Entry, _ int) bool {
			return len(group) > limit
		}), func(group []*Entry) int { return len(group) })
		var outliers map[*Entry]bool
		if mainMass*2 >= len(entries) {
			outliers = MinorClusters(groups, limit)
		}

		// A collection row drops the epoch prefix here; everything else in the
		// section passes through as it came.
		lines := script.AlignLsBodies(lo.Map(rows, func(r row, _ int) string {
			if r.entry == nil {
				return r.text
			}
			return r.entry.Row
		}))
		var notes []model.LineMatch
		for index, r := range rows {
			if r.entry == nil {
				continue
			}
			marker := OutlierMarker(r.entry.Mtime, r.entry.Ctime, outliers[r.entry], moment)
			if verdict := OutlierMatch(EntryPath(r.entry), marker, len(lines[index])); verdict != nil {
				notes = append(notes, model.LineMatch{Line: index, Match: *verdict})
			}
		}
		return &model.Shaped{Text: strings.Join(lines, "\n"), Notes: notes}
	}
}

func entryMtime(e *Entry) float64 { return e.Mtime }
