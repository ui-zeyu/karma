// Package linux is the Linux check catalog: read-only inspection assembled by
// aspect. Group order is the aspect order in the report.
package linux

import (
	"context"
	"fmt"
	"slices"

	"karma/internal/model"
	"karma/internal/script"
)

// filesTier is the read-a-file-list tier: one `== path` section per file,
// missing files skipped, each body shaped by the shell command's native
// counterpart (cat reads the file whole, tail keeps the last n lines).
func filesTier(label string, shellCmd string, transform func(string) string, paths []string) model.Probe {
	return model.Probe{Label: label, Inv: model.Dual{
		Run:    func(context.Context) (string, error) { return readSections(paths, transform), nil },
		Script: script.ReadFiles(paths, shellCmd, true),
	}}
}

// readFilesCheck is the cat-a-file-list tier pair.
func readFilesCheck(paths ...string) []model.Probe {
	return []model.Probe{filesTier("cat", `cat "$f"`, nil, paths)}
}

// tailFilesCheck reads the tail of every file in the list.
func tailFilesCheck(n int, paths ...string) []model.Probe {
	return []model.Probe{filesTier("tail", fmt.Sprintf(`tail -n %d "$f"`, n), tailLines(n), paths)}
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
