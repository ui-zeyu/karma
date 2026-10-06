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
)

// Docker mirrors dockerScript: containers then images, one blank line
// between.
func Docker(ctx context.Context) (string, error) {
	if !haveBinary("docker") {
		return "", model.ErrTierUnavailable
	}
	ps := runHost(ctx, []string{"docker", "ps", "-a"}, false)
	images := runHost(ctx, []string{"docker", "images"}, false)
	return ps.out + "\n" + images.out, nil
}

// forensics appends the in-place forensics sections for one file list —
// forensicsBlock's mirror: the type rows, then the ls -l rows; an empty list
// appends nothing. Both sections are built in process, so no hooked libc or
// PATH shadow stands between the evidence and this process.
func forensics(b *strings.Builder, files []string) {
	if len(files) == 0 {
		return
	}
	b.WriteString("== file\n")
	b.WriteString(localfs.FileRows(files))
	b.WriteString("== ls\n")
	b.WriteString(localfs.LsRows(files))
}

// verifyFacts classifies one verifier-listed path the way the shell tier's
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

// verifyDetail renders the `== file` and `== ls` forensics for the paths the
// body names, built in process by localfs rather than through the target's
// binaries.
func verifyDetail(paths []string) (string, string) {
	return localfs.FileRows(paths), localfs.LsRows(paths)
}

// PkgVerify mirrors PkgVerifyScript: the files that can be a finding are named
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

// PkgHistory mirrors the check's pkgHistoryScript: the apt/dpkg log tails it
// hands in, then the dnf/yum transaction history — dnf's output uncapped and
// yum's head-capped at the same window, the pipe binding the script itself
// spells.
func PkgHistory(paths []string, lines int) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		return pkgHistoryBody(ctx, paths, lines), nil
	}
}

func pkgHistoryBody(ctx context.Context, paths []string, lines int) string {
	body := localfs.ReadSections(paths, localfs.TailLines(lines))
	body += "== dnf history\n"
	// The script's `dnf history || yum history | head` keeps dnf's own output
	// either way and only runs yum when dnf failed.
	dnf := runHost(ctx, []string{"dnf", "history"}, false)
	body += dnf.out
	if !dnf.ok {
		if yum := runHost(ctx, []string{"yum", "history"}, false); yum.out != "" {
			body += headLines(yum.out, lines)
		}
	}
	return body
}

// headLines caps a body at n lines.
func headLines(text string, n int) string {
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n") + "\n"
}

// AuthBinaries mirrors the check's authBinScript: the existing programs among
// the paths it hands in, then the shared forensics block.
func AuthBinaries(paths []string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var b strings.Builder
		forensics(&b, localfs.ExpandFiles(paths))
		return b.String(), nil
	}
}

// UnownedFiles mirrors UnownedScript: the entries one level inside each system
// directory that the package database does not list. A host with neither
// package manager has no database to compare against, which is the tier's
// "no answer here" rather than an empty answer.
func UnownedFiles(dirs []string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		roots := unownedRoots(dirs)
		if len(roots) == 0 {
			return "", nil
		}
		owned, ok := unownedOwned(ctx, roots)
		if !ok {
			return "", model.ErrTierUnavailable
		}
		return script.UnownedBody(unownedEntries(roots), owned), nil
	}
}

// unownedRoots resolves each directory to its canonical path and drops the
// repeats: usrmerge's /bin and /usr/bin are one directory, and the script
// tier's readlink -f loop reaches the same set.
func unownedRoots(dirs []string) []string {
	var roots []string
	seen := map[string]bool{}
	for _, dir := range dirs {
		resolved, err := filepath.EvalSymlinks(dir)
		if err != nil || seen[resolved] {
			continue
		}
		seen[resolved] = true
		roots = append(roots, resolved)
	}
	return roots
}

// unownedEntries lists one directory level, leaving out the
// update-alternatives links the script's find -lname filter leaves out.
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

// unownedOwned reads the paths the package database knows, through the same two
// commands the script tier runs: dpkg searched with one wildcard pattern per
// directory, or rpm listing every file it ships. A pattern that matches nothing
// makes dpkg complain on stderr and a directory whose every file is unowned is
// exactly the case this check exists for, so the complaint is dropped.
func unownedOwned(ctx context.Context, roots []string) ([]string, bool) {
	if haveBinary("dpkg") {
		argv := []string{"dpkg", "-S"}
		for _, root := range roots {
			argv = append(argv, root+"/*")
		}
		return ownedRows(runHostQuiet(ctx, argv, true).out), true
	}
	if haveBinary("rpm") {
		return ownedRows(runHostQuiet(ctx, []string{"rpm", "-qa", "--qf", `[%{FILENAMES}\n]`}, true).out), true
	}
	return nil, false
}

// ownedRows splits a package manager's file listing the way the script tier's
// `sed 's/^.*: //'` does: a dpkg row is `package: path`, a multiarch row
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
