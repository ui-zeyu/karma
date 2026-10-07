// Package linux is the Linux check catalog: read-only inspection assembled by
// aspect. Group order is the aspect order in the report.
package linux

import (
	"context"
	"fmt"
	"slices"
	"time"

	"karma/internal/cluster"
	"karma/internal/define"
	"karma/internal/localfs"
	"karma/internal/model"
	"karma/internal/script"
)

// openScanLines is the row cap an open scan carries: a listing, a walk or a
// signature grep that has produced this many rows has produced volume rather
// than evidence, so the source is stopped and the panel marks the body
// truncated. A tier that wants a fixed number of rows instead declares
// model.Shape (a listing head, a sorted view's top N), which reports the rows
// it asked for rather than a cut.
const openScanLines = 200

// filesTier is the read-a-file-list tier pair: one `== path` section per file,
// missing files skipped. The native source reads the files in process; the sh
// source runs the same read as a shell loop over the same list, shaped by the
// shell command's native counterpart (cat reads the file whole, tail keeps the
// last n lines), so either source hands the reading layer the same sections.
func filesTier(label string, shellCmd string, transform func(string) string, paths []string) []model.Step {
	return []model.Step{
		{{Label: label, Inv: model.Native{Body: func(context.Context) (string, error) {
			return localfs.ReadSections(paths, transform), nil
		}}}},
		{{Label: label + "-sh", Inv: model.Sh(script.ReadFiles(paths, shellCmd, true))}},
	}
}

// readFilesCheck is the cat-a-file-list tier pair.
func readFilesCheck(paths ...string) []model.Step {
	return filesTier("cat", `cat "$f"`, nil, paths)
}

// tailFilesCheck reads the tail of every file in the list.
func tailFilesCheck(n int, paths ...string) []model.Step {
	return filesTier("tail", fmt.Sprintf(`tail -n %d "$f"`, n), localfs.TailLines(n), paths)
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
// in-process walk and the find pipeline are the two sources' readings of the
// same directories, so the check declares one tier per source.
func listingCheck(id, title string, aspect model.Aspect, dirs []string, head int, rules []model.Matcher) *model.Check {
	return define.LinuxCheck(id, title, aspect,
		[]model.Step{
			{{Label: "find", Inv: model.Native{Body: localfs.Listing(dirs, head)}}},
			// The sh source's reading of the same directories: one find -printf
			// per directory, the same ls -l row shape and the same head.
			{{Label: "find-sh", Inv: model.Sh(script.ListingSections(dirs, head))}},
		},
		define.CheckOpt{Rules: rules, Syntax: model.SyntaxLsL, Normalize: listingNormalize})
}
