// native tiers of the package checks: container instances, package integrity
// verification with in-place forensics, transaction history, and auth-chain
// binaries.

package linux

import (
	"context"
	"os"
	"slices"
	"strings"

	"karma/internal/model"
)

// nativeDocker mirrors dockerScript: containers then images, one blank line
// between.
func nativeDocker(ctx context.Context) (string, error) {
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
	b.WriteString(fileRows(files))
	b.WriteString("== ls\n")
	b.WriteString(lsRows(files))
}

// sortedPaths returns the paths in the listing tier's sorted order.
func sortedPaths(files []string) []string {
	sorted := slices.Clone(files)
	slices.Sort(sorted)
	return sorted
}

// lsRows renders the `== ls` forensics section for one file list. The
// attributes come from lstat in process, not from a hooked libc: a setuid bit
// added to an auth binary is the kind of fact an LD_PRELOAD ls would hide.
// Rows are the listing tier's shape (script.LSBodyPrintf) — the same rows every
// other local listing prints — so they differ from GNU ls's column padding, and
// the date is clock-shaped. ls sorts its arguments itself, and a vanished file
// costs only its row (ls reports it on stderr, which the script tier drops).
func lsRows(files []string) string {
	names := newNameCache()
	var b strings.Builder
	for _, path := range sortedPaths(files) {
		if info, err := os.Lstat(path); err == nil {
			b.WriteString(lsBody(info, path, names))
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// nativePkgVerify mirrors verifyScript: the verifier's own output when
// non-empty, then forensics on the md5-failed files; no differences is an
// empty answer, not a fall-through to the other package manager.
func nativePkgVerify(argv []string) func(context.Context) (string, error) {
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

// nativePkgHistory mirrors pkgHistoryScript: the apt/dpkg log tails, then the
// dnf/yum transaction history — dnf's output uncapped and yum's head-capped,
// the pipe binding the script itself spells.
func nativePkgHistory(ctx context.Context) (string, error) {
	body := readSections([]string{"/var/log/apt/history.log", "/var/log/dpkg.log"}, tailLines(300))
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
	return body, nil
}

// headLines caps a body at n lines.
func headLines(text string, n int) string {
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n") + "\n"
}

// authBinPaths is the auth-chain program list; the globs cover both the
// multiarch and lib64 PAM layouts.
var authBinPaths = []string{
	"/usr/sbin/sshd", "/usr/bin/login", "/usr/bin/su", "/usr/bin/sudo",
	"/usr/bin/passwd", "/usr/sbin/unix_chkpwd", "/sbin/unix_chkpwd",
	"/usr/lib*/security/pam_unix.so", "/lib*/security/pam_unix.so",
}

// nativeAuthBinaries mirrors authBinScript: existing programs only, then the
// shared forensics block.
func nativeAuthBinaries(ctx context.Context) (string, error) {
	var b strings.Builder
	forensics(&b, expandFiles(authBinPaths))
	return b.String(), nil
}
