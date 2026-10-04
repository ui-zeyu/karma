// Package linux is the Linux check catalog: read-only inspection assembled by
// aspect. Group order is the aspect order in the report.
package linux

import (
	"slices"

	"karma/internal/model"
	"karma/internal/script"
)

// readFilesProbe is the cat-a-file-list probe: one `== path` section per file,
// missing files skipped and read noise quiet.
func readFilesProbe(paths ...string) model.Probe {
	return model.Probe{Label: "cat", Inv: model.Shell{Script: script.ReadFiles(paths, `cat "$f"`, true)}}
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
