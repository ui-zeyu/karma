// native tiers of the package checks: container instances, package integrity
// verification with in-place forensics, transaction history, and auth-chain
// binaries.

package native

import (
	"context"
	"strings"

	"karma/internal/localfs"
	"karma/internal/model"
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

// verifyChanged parses dpkg -V / rpm -Va output: column 3 of the first field
// is the md5 flag, and the files it failed land in the forensics block —
// awk 'substr($1, 3, 1) == "5" {print $NF}'.
func verifyChanged(verifyOut string) []string {
	var changed []string
	for _, line := range strings.Split(verifyOut, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || len(fields[0]) < 3 {
			continue
		}
		if fields[0][2] == '5' {
			changed = append(changed, fields[len(fields)-1])
		}
	}
	return changed
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

// PkgVerify mirrors verifyScript: the verifier's own output when
// non-empty, then forensics on the md5-failed files; no differences is an
// empty answer, not a fall-through to the other package manager.
func PkgVerify(argv []string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		if !haveBinary(argv[0]) {
			// The other package manager's tier is next in the chain.
			return "", model.ErrTierUnavailable
		}
		res := runHost(ctx, argv, false)
		var b strings.Builder
		if strings.TrimRight(res.out, "\n") != "" {
			b.WriteString(res.out)
		}
		forensics(&b, verifyChanged(res.out))
		return b.String(), nil
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
