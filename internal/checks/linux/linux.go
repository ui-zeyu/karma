// Package linux is the Linux check catalog: read-only inspection assembled by
// aspect. Group order is the aspect order in the report.
package linux

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/samber/lo"

	"karma/internal/cluster"
	"karma/internal/define"
	"karma/internal/localfs"
	"karma/internal/model"
	"karma/internal/script"
)

// openScanLines is the row cap an open scan carries: a listing, a walk or a
// signature grep that has produced this many rows has produced volume rather
// than evidence, so the source is stopped and the panel marks the body
// truncated. A tier that stops at the shape it wants uses Probe.Head instead.
const openScanLines = 200

// filesTier is the read-a-file-list tier: one `== path` section per file,
// missing files skipped, each body shaped by the shell command's native
// counterpart (cat reads the file whole, tail keeps the last n lines).
func filesTier(label string, shellCmd string, transform func(string) string, paths []string) model.Probe {
	return model.Probe{Label: label, Inv: model.Dual{
		Run:    func(context.Context) (string, error) { return localfs.ReadSections(paths, transform), nil },
		Script: script.ReadFiles(paths, shellCmd, true),
	}}
}

// readFilesCheck is the cat-a-file-list tier pair.
func readFilesCheck(paths ...string) []model.Step {
	return []model.Step{{filesTier("cat", `cat "$f"`, nil, paths)}}
}

// findNameArgs renders a find name test alternation: one -name/-iname word per
// pattern, joined by -o. The web-script and miner walks each spell their own
// option and pattern list, and the same helper builds both.
func findNameArgs(option string, patterns []string) string {
	return strings.Join(lo.Map(patterns, func(pattern string, _ int) string {
		return option + " '" + pattern + "'"
	}), " -o ")
}

// tailFilesCheck reads the tail of every file in the list.
func tailFilesCheck(n int, paths ...string) []model.Step {
	return []model.Step{{filesTier("tail", fmt.Sprintf(`tail -n %d "$f"`, n), localfs.TailLines(n), paths)}}
}

// All is every Linux check; catalog-level validation lives in the checks package.
var All = slices.Concat(
	SystemChecks,
	IdentityChecks,
	ProcessChecks,
	NetworkChecks,
	ServiceChecks,
	PersistenceChecks,
	FilesystemChecks,
	LogsChecks,
	KernelChecks,
	PackageChecks,
)

// listingNormalize is the clustering normalizer of every listing-shaped tier:
// whatever produced the rows (a find pipeline, the in-process walk, a host
// tool), they are clustered and graded the same way before they are shown.
var listingNormalize = cluster.ListingNormalize(time.Now)

// listingCheck is a directory-listing check: one section per directory, rows
// in ls -l shape capped at head, clustered locally to mark outliers. The
// in-process branch and the find pipeline are two implementations of the one
// tier, so the check is declared once for both channels.
func listingCheck(id, title string, aspect model.Aspect, dirs []string, head int, rules []model.Rule) *model.Check {
	return define.LinuxCheck(id, title, aspect,
		[]model.Step{{{Label: "find", Inv: model.Dual{
			Run:    localfs.Listing(dirs, head),
			Script: script.ListingSections(dirs, head),
		}}}},
		define.CheckOpt{Rules: rules, Syntax: model.SyntaxLsL, Normalize: listingNormalize})
}
