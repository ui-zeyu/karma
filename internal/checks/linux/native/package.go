// native tiers of the package checks: container instances, package integrity
// verification with in-place forensics, transaction history, and auth-chain
// binaries.

package native

import (
	"context"
	"errors"
	"io/fs"
	"os"
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
// yum's head-capped, the pipe binding the script itself spells.
func PkgHistory(paths []string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		return pkgHistoryBody(ctx, paths), nil
	}
}

func pkgHistoryBody(ctx context.Context, paths []string) string {
	body := localfs.ReadSections(paths, localfs.TailLines(300))
	body += "== dnf history\n"
	// The script's `dnf history || yum history | head` keeps dnf's own output
	// either way and only runs yum when dnf failed.
	dnf := runHost(ctx, []string{"dnf", "history"}, false)
	body += dnf.out
	if !dnf.ok {
		if yum := runHost(ctx, []string{"yum", "history"}, false); yum.out != "" {
			body += headLines(yum.out, 300)
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
