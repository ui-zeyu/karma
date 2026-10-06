// The mtime subcommand's check: mtime clustering of user-specified directories.
//
// Collect one find -printf metadata stream (mtime, ctime, target-local time, size,
// path) and split it into clusters locally in the cluster package; the check itself
// only renders the timeline and file lines. Deploys and installs are large,
// contiguous clusters, while a dropped trojan is often a small handful of files
// isolated in time from the main group.

package linux

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/samber/lo"

	"karma/internal/checks/linux/native"
	"karma/internal/cluster"
	"karma/internal/define"
	"karma/internal/model"
	"karma/internal/script"
	"karma/internal/textutil"
)

const huntID = "mtime-hunt"

const barWidth = 30 // max cells in the timeline bar

// scanBytes: a large directory's metadata stream can reach tens of MB, so this
// check raises its own read limit (about 400k files).
const scanBytes = 64 * 1024 * 1024

// huntTimeout: a large tree's metadata stream takes longer to collect than the
// default per-command timeout allows.
const huntTimeout = 60 * time.Second

// findPrintf: mtime, ctime (epoch seconds), target-local date and time, bytes,
// path, tab-separated.
const findPrintf = `%T@\t%C@\t%TY-%Tm-%Td\t%TH:%TM:%TS\t%s\t%p\n`

// huntPruneDirs: the virtual filesystems a sweep from / must not descend into.
// They hold no file metadata worth clustering, and walking them floods the
// stream. The find tier prunes them by path, the local walk decides per
// directory, so both cover the same set.
var huntPruneDirs = []string{"/proc", "/sys", "/dev"}

// huntPrune is that list as the find expression -prune takes.
var huntPrune = strings.Join(lo.Map(huntPruneDirs, func(dir string, _ int) string { return "-path " + dir }), " -o ")

// huntScript: one section per directory; an absent or unreadable directory yields
// an empty body, and the normalizer adds an explanatory line. -xdev keeps the walk
// on the given directory's own filesystem, and the virtual filesystems are pruned
// by name so a sweep from / stays on the disk.
func huntScript(dirs []string) string {
	words := strings.Join(lo.Map(dirs, func(dir string, _ int) string { return script.Quote(dir) }), " ")
	return fmt.Sprintf("for d in %s; do\n  echo \"== $d\"\n  find \"$d\" -xdev \\( %s \\) -prune -o -type f -printf '%s' 2>/dev/null\ndone",
		words, huntPrune, findPrintf)
}

// huntNormalize turns one section body (a directory's find output) into a timeline
// plus outlier/marked lines.
//
// The title parameter comes from the reader's section split; the normalizer looks
// only at the body. The full listing never enters the body: directory listings are
// the job of checks like key-dirs and tmp-listing, so only the cluster shape and
// signal lines remain, and the evidence can be reproduced with one find on the
// target. An outlier line's severity and reason become a span right here during
// normalization (OutlierMatch); the verdict shows as the line's color plus its
// ⟨reason⟩ annotation, the text carries no prefix.
func huntNormalize(now func() time.Time) model.Normalizer {
	return func(_ string, text string) *model.Shaped {
		moment := now()
		var files []*cluster.FindRow
		var raw []string
		for line := range textutil.Lines(text) {
			if parsed := cluster.ParseFindRow(line); parsed != nil {
				files = append(files, parsed)
			} else {
				raw = append(raw, line)
			}
		}
		if len(files) == 0 {
			return &model.Shaped{Text: cmp.Or(strings.Join(raw, "\n"), "(no files or unreadable)")}
		}

		groups := cluster.ClusterByMtime(files, findRowMtime, findRowPath)
		limit := cluster.OutlierSizeLimit(len(files))
		// Without a large cluster there is no main group to compare against, so a small
		// directory that is all scattered is not treated as outliers
		var outliers map[*cluster.FindRow]bool
		if lo.SomeBy(groups, func(group []*cluster.FindRow) bool { return len(group) > limit }) {
			outliers = cluster.MinorClusters(groups, limit)
		}
		// In the main group only marked lines are printed (mtime in the future); signals
		// come first, marked lines are always printed
		flagged := lo.Filter(files, func(item *cluster.FindRow, _ int) bool {
			return !outliers[item] && cluster.OutlierMarker(item.Mtime, item.Ctime, false, moment) != ""
		})

		sized := slices.Concat(lo.Keys(outliers), flagged)
		width := lo.Max(lo.Map(sized, func(item *cluster.FindRow, _ int) int {
			return len(human(item.Nbytes))
		}))
		lines := timeline(groups)
		var notes []model.LineMatch
		// Outlier lines first, then future-timestamp lines from the main group, each with
		// the most recent first
		for _, item := range slices.Concat(byRecency(lo.Keys(outliers)), byRecency(flagged)) {
			marker := cluster.OutlierMarker(item.Mtime, item.Ctime, outliers[item], moment)
			line := fmt.Sprintf("%s  %*s  %s", item.Stamp, width, human(item.Nbytes), item.Path)
			lines = append(lines, line)
			if verdict := cluster.OutlierMatch(item.Path, marker, len(line)); verdict != nil {
				notes = append(notes, model.LineMatch{Line: len(lines) - 1, Match: *verdict})
			}
		}
		lines = append(lines, raw...)
		return &model.Shaped{Text: strings.Join(lines, "\n"), Notes: notes}
	}
}

// byRecency: most recent first (same instant sorted by ascending path).
func byRecency(files []*cluster.FindRow) []*cluster.FindRow {
	ordered := slices.Clone(files)
	slices.SortStableFunc(ordered, func(a, b *cluster.FindRow) int {
		return cmp.Or(cmp.Compare(b.Mtime, a.Mtime), cmp.Compare(a.Path, b.Path))
	})
	return ordered
}

func findRowMtime(r *cluster.FindRow) float64 { return r.Mtime }
func findRowPath(r *cluster.FindRow) string   { return r.Path }

var units = []string{"", "K", "M", "G"}

// human renders human-readable sizes like ls -h: after unit conversion, values
// below ten get one decimal, while bytes get no unit or decimal.
func human(nbytes int) string {
	size := float64(nbytes)
	index := 0
	for size >= 1024 && index < len(units)-1 {
		size /= 1024
		index++
	}
	if index == 0 {
		return fmt.Sprintf("%d", nbytes)
	}
	if size < 10 {
		return fmt.Sprintf("%.1f%s", size, units[index])
	}
	return fmt.Sprintf("%d%s", int(size), units[index])
}

// span is a cluster's time span: same-day includes the time (to the minute), a
// day crossing writes only dates, and the same year omits the later year.
func span(group []*cluster.FindRow) string {
	first, last := group[0], group[len(group)-1]
	if first.Date == last.Date {
		start, end := first.Stamp[11:16], last.Stamp[11:16]
		if start == end {
			return first.Date + " " + start
		}
		return first.Date + " " + start + " ~ " + end
	}
	if first.Date[:4] == last.Date[:4] {
		return first.Date + " ~ " + last.Date[5:]
	}
	return first.Date + " ~ " + last.Date
}

// bar normalizes bar length to the largest cluster, at least one cell.
func bar(count, top int) string {
	return strings.Repeat("█", max(1, count*barWidth/top))
}

// timeline: fewer-cluster groups first (same count, newer first), bar length
// normalized to the largest cluster in the section.
func timeline(groups [][]*cluster.FindRow) []string {
	topCount := lo.Max(lo.Map(groups, func(group []*cluster.FindRow, _ int) int { return len(group) }))
	width := len(fmt.Sprintf("%d", topCount))
	spanWidth := lo.Max(lo.Map(groups, func(group []*cluster.FindRow, _ int) int { return len(span(group)) }))
	ordered := slices.Clone(groups)
	slices.SortStableFunc(ordered, func(a, b []*cluster.FindRow) int {
		return cmp.Or(
			cmp.Compare(len(a), len(b)),
			cmp.Compare(b[len(b)-1].Mtime, a[len(a)-1].Mtime),
		)
	})
	return lo.Map(ordered, func(group []*cluster.FindRow, _ int) string {
		return fmt.Sprintf("%-*s  %s %*d", spanWidth, span(group), bar(len(group), topCount), width, len(group))
	})
}

// HuntCheck builds an mtime-clustering check for the user's directories, appended
// at the end of the catalog for this run.
func HuntCheck(dirs []string) *model.Check {
	return define.LinuxCheck(huntID, "Mtime clustering (user-specified directories)", model.AspectFilesystem,
		[]model.Step{{{Label: "find", Inv: model.Dual{Run: native.Hunt(dirs, huntPruneDirs), Script: huntScript(dirs)}}}},
		define.CheckOpt{
			Normalize: huntNormalize(time.Now),
			ScanBytes: scanBytes,
			Timeout:   huntTimeout,
		})
}
