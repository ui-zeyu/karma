// native tiers of the package checks: container instances, package integrity
// verification with in-place forensics, transaction history, and auth-chain
// binaries.

package native

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"karma/internal/localfs"
	"karma/internal/model"
	"karma/internal/script"
	"karma/internal/textutil"
)

// Docker prints containers then images, one blank line between.
func Docker(ctx context.Context) (string, error) {
	if !haveBinary("docker") {
		return "", model.ErrTierUnavailable
	}
	ps := runHost(ctx, []string{"docker", "ps", "-a"}, false)
	images := runHost(ctx, []string{"docker", "images"}, false)
	return ps.out + "\n" + images.out, nil
}

// verifyFacts classifies one verifier-listed path the way the sh source's
// file(1) and ls -l answers do: a path that is gone is missing (dpkg's flag
// field cannot tell a deleted file from a modified one), an ELF object or an
// executable is named on its own, anything else is counted by PkgVerifyBody
// under its directory.
func verifyFacts(path string) script.VerifyFacts {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return script.VerifyFacts{Missing: true}
	}
	return script.VerifyFacts{Key: localfs.ProgramFile(path)}
}

// verifyDetail renders the type and attribute rows for the paths the body names,
// built in process by localfs rather than through the target's binaries; an empty
// list renders neither.
func verifyDetail(paths []string) (string, string) {
	if len(paths) == 0 {
		return "", ""
	}
	return localfs.FileRows(paths), localfs.LsRows(paths)
}

// PkgVerify names the files that can be a finding
// with their type and attributes, the rest are counted per directory. No
// differences is an empty answer, not a fall-through to the other package
// manager.
func PkgVerify(argv []string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		if !haveBinary(argv[0]) {
			// The other package manager's tier is next in the chain.
			return "", model.ErrTierUnavailable
		}
		res := runHost(ctx, argv, false)
		return script.PkgVerifyBody(res.out, verifyFacts, verifyDetail), nil
	}
}

// DnfHistory reads the transaction database: dnf's own answer, or yum's
// head-capped at the same window when dnf is not there.
func DnfHistory(lines int) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		// The script's `dnf history || yum history | head` keeps dnf's own output
		// either way and only runs yum when dnf failed.
		dnf := runHost(ctx, []string{"dnf", "history"}, false)
		if dnf.ok {
			return dnf.out, nil
		}
		if yum := runHost(ctx, []string{"yum", "history"}, false); yum.out != "" {
			return headLines(yum.out, lines), nil
		}
		return "", nil
	}
}

// headLines caps a body at n lines the way `| head -n` does: the first n lines,
// each terminated, so the section that follows cannot glue onto the last one.
func headLines(text string, n int) string {
	head, _ := textutil.Head(text, n)
	if !strings.HasSuffix(head, "\n") {
		head += "\n"
	}
	return head
}

// AuthBinTypes types the existing programs among the paths it hands in, in
// process — nothing stands between the answer and this process.
func AuthBinTypes(paths []string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		return localfs.FileRows(localfs.ExpandFiles(paths)), nil
	}
}

// AuthBinAttrs lists the same programs' attributes, in process.
func AuthBinAttrs(paths []string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		return localfs.LsRows(localfs.ExpandFiles(paths)), nil
	}
}

// UnownedFiles lists the entries one level inside each system
// directory that the package database does not list. A host with neither
// package manager has no database to compare against, which is the tier's
// "no answer here" rather than an empty answer.
func UnownedFiles(dirs []string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		roots, spellings := unownedSpellings(dirs)
		if len(roots) == 0 {
			return "", nil
		}
		owned, ok := unownedOwned(ctx, spellings)
		if !ok {
			return "", model.ErrTierUnavailable
		}
		return script.UnownedBody(unownedEntries(roots), owned), nil
	}
}

// unownedSpelling pairs one requested directory with its canonical path.
// usrmerge's /bin and /usr/bin are one directory, so the canonical roots are
// deduplicated — but every original spelling is kept: dpkg's database still
// records the pre-merge paths, so both spellings are queried and the owned
// rows are rewritten into the canonical one before the comparison.
type unownedSpelling struct {
	original  string
	canonical string
}

// unownedSpellings resolves each directory and returns the deduplicated
// canonical roots with every spelling that reached each.
func unownedSpellings(dirs []string) ([]string, []unownedSpelling) {
	var (
		roots     []string
		spellings []unownedSpelling
	)
	seen := map[string]bool{}
	for _, dir := range dirs {
		resolved, err := filepath.EvalSymlinks(dir)
		if err != nil {
			continue
		}
		spellings = append(spellings, unownedSpelling{original: dir, canonical: resolved})
		if !seen[resolved] {
			seen[resolved] = true
			roots = append(roots, resolved)
		}
	}
	return roots, spellings
}

// unownedEntries lists one directory level, leaving out the update-alternatives
// links update-alternatives manages its targets, so no package owns them.
func unownedEntries(roots []string) []string {
	var found []string
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			path := root + "/" + entry.Name()
			target, err := os.Readlink(path)
			if err == nil && strings.HasPrefix(target, "/etc/alternatives/") {
				continue
			}
			found = append(found, path)
		}
	}
	return found
}

// unownedOwned reads the paths the package database knows, through the two
// commands a package manager answers with: dpkg searched with one wildcard pattern
// per directory spelling, or rpm listing every file it ships. A pattern that
// matches nothing makes dpkg complain on stderr and a directory whose every
// file is unowned is exactly the case this check exists for, so the complaint
// is dropped. The dpkg rows are rewritten from the pre-merge spelling into
// the canonical root, the spelling the walk found its paths under.
func unownedOwned(ctx context.Context, spellings []unownedSpelling) ([]string, bool) {
	if haveBinary("dpkg") {
		argv := []string{"dpkg", "-S"}
		for _, s := range spellings {
			argv = append(argv, s.original+"/*")
		}
		return canonicalRows(runHostQuiet(ctx, argv, true).out, spellings), true
	}
	if haveBinary("rpm") {
		return ownedRows(runHostQuiet(ctx, []string{"rpm", "-qa", "--qf", `[%{FILENAMES}\n]`}, true).out), true
	}
	return nil, false
}

// canonicalRows parses the manager's listing and rewrites pre-merge spellings
// to their canonical root: the found paths and the owned paths must be the
// same strings to compare.
func canonicalRows(out string, spellings []unownedSpelling) []string {
	rows := ownedRows(out)
	for i, path := range rows {
		for _, s := range spellings {
			if s.original != s.canonical && strings.HasPrefix(path, s.original+"/") {
				rows[i] = s.canonical + path[len(s.original):]
				break
			}
		}
	}
	return rows
}

// ownedRows splits a package manager's file listing: a dpkg row is
// `package: path`, a multiarch row
// `package:arch: path`, so the path is what follows the last separator, and a
// row without one is already a path.
func ownedRows(out string) []string {
	var paths []string
	for line := range strings.SplitSeq(strings.TrimSuffix(out, "\n"), "\n") {
		if cut := strings.LastIndex(line, ": "); cut >= 0 {
			line = line[cut+2:]
		}
		if line != "" {
			paths = append(paths, line)
		}
	}
	return paths
}
