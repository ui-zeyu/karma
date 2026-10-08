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

// filesTier is the read-a-file-list tier pair: one section per file, titled with
// the path, missing files skipped. The native source reads the files in process;
// the sh source asks for the list and then reads one file per call — a section
// boundary is the collection's own statement, never a line inside the bytes it
// read, so neither source can be talked into a section by a file's contents.
//
// The in-process list is the sh list's own spelling (localfs.ListFiles), so both
// sources name the same files in the same order. adapt is the tier's own dialect
// alignment, run on every section the tier answered with (nil for none).
func filesTier(label, shellCmd string, transform func(string) string, adapt model.Normalizer, paths []string) []model.Step {
	return []model.Step{
		{{Label: label, Adapt: adapt, Files: &model.Files{
			List: model.Native{Body: listFiles(paths)},
			Read: func(path string) model.Invocation { return model.Native{Body: readFile(path, transform)} },
		}}},
		{{Label: label + "-sh", Adapt: adapt, Files: &model.Files{
			List: model.Sh(script.ListFiles(paths)),
			Read: func(path string) model.Invocation { return model.Sh(script.ReadFile(path, shellCmd)) },
		}}},
	}
}

// listFiles is the in-process file list.
func listFiles(paths []string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return localfs.ListFiles(paths), nil }
}

// readFile is the in-process read of one file of the list.
func readFile(path string, transform func(string) string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return localfs.ReadBody(path, transform), nil }
}

// listDirs is the in-process directory list.
func listDirs(dirs []string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return localfs.ListDirs(dirs), nil }
}

// listingBody is the in-process listing of one directory.
func dirListing(dir string, head int) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return localfs.ListingBody(dir, head), nil }
}

// readFilesCheck is the cat-a-file-list tier pair.
func readFilesCheck(paths ...string) []model.Step {
	return filesTier("cat", `cat "$f"`, nil, nil, paths)
}

// tailFilesCheck reads the tail of every file in the list.
func tailFilesCheck(n int, paths ...string) []model.Step {
	return filesTier("tail", fmt.Sprintf(`tail -n %d "$f"`, n), localfs.TailLines(n), nil, paths)
}

// withCap sets one row cap on every probe of a tier: the cap bounds the section
// each member answers with.
func withCap(steps []model.Step, cap model.RowCap) []model.Step {
	for index := range steps {
		for probe := range steps[index] {
			steps[index][probe].Cap = cap
		}
	}
	return steps
}

// listingTier is a directory-listing tier pair: one section per directory, rows
// in ls -l shape capped at head. The in-process walk and the find pipeline are
// the two sources' readings of the same directories, so the check declares one
// tier per source.
func listingTier(label string, dirs []string, head int) []model.Step {
	return []model.Step{
		{{Label: label, Files: &model.Files{
			List: model.Native{Body: listDirs(dirs)},
			Read: func(dir string) model.Invocation { return model.Native{Body: dirListing(dir, head)} },
		}}},
		{{Label: label + "-sh", Files: &model.Files{
			List: model.Sh(script.ListDirs(dirs)),
			Read: func(dir string) model.Invocation { return model.Sh(script.ListingFind(dir, head)) },
		}}},
	}
}

// surface is one named part of a tier: the section title it answers with, the
// in-process body, the shell spelling of the same read, and the row cap the
// part's own answer wants (the zero cap is no cap).
type surface struct {
	Title  string
	Native func(context.Context) (string, error)
	Script string
	Cap    model.RowCap
}

// surfacesTier is a tier pair that answers with one section per surface: one
// probe per surface on each source, each with its own call and its own title.
// A surface the target does not have — a missing binary, a family that does not
// apply — reports itself unavailable and its section simply is not there, which
// is how the shell's own `if command -v X` guard is spelled now. adapt is the
// tier's own dialect alignment, run on every section the tier answered with.
func surfacesTier(label string, adapt model.Normalizer, surfaces []surface) []model.Step {
	inProcess := make(model.Step, 0, len(surfaces))
	shell := make(model.Step, 0, len(surfaces))
	for _, part := range surfaces {
		inProcess = append(inProcess, model.Probe{
			Label: label, Title: part.Title, Inv: model.Native{Body: part.Native},
			Adapt: adapt, Cap: part.Cap,
		})
		shell = append(shell, model.Probe{
			Label: label + "-sh", Title: part.Title, Inv: model.Sh(part.Script),
			Adapt: adapt, Cap: part.Cap,
		})
	}
	return []model.Step{inProcess, shell}
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
// in ls -l shape capped at head, clustered locally to mark outliers.
func listingCheck(id, title string, aspect model.Aspect, dirs []string, head int, rules []model.Matcher) *model.Check {
	return define.LinuxCheck(id, title, aspect,
		listingTier("find", dirs, head),
		define.CheckOpt{Rules: rules, Syntax: model.SyntaxLsL, Normalize: listingNormalize})
}
