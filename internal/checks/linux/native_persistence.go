// native tiers of the persistence checks: cron surfaces, boot scripts,
// startup files, skel listings, generators, udev rules, motd, and .pth.

package linux

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// nativeCron mirrors cronScript: the crontab files, the spool, then the
// invoking user's own crontab.
func nativeCron(ctx context.Context) (string, error) {
	body := readSections([]string{
		"/etc/crontab", "/etc/anacrontab",
		"/etc/cron.d/*",
		"/etc/cron.daily/*",
		"/etc/cron.hourly/*",
		"/etc/cron.weekly/*",
		"/etc/cron.monthly/*",
		"/var/spool/cron/crontabs/*",
		"/var/spool/cron/*",
		"/var/spool/cron/atspool/*",
		"/var/spool/cron/atjobs/*",
	}, nil)
	return body + "== crontab -l\n" + runHost(ctx, []string{"crontab", "-l"}, false).out, nil
}

// nativeLdPreload reads the preload list bare, exactly like the cat tier: a
// `== path` section title would run the entry rule (titles meet the rules
// too) and flag the file's mere existence.
func nativeLdPreload(ctx context.Context) (string, error) {
	body, err := os.ReadFile("/etc/ld.so.preload")
	if err != nil {
		return "", nil
	}
	return string(body), nil
}

// nativeSkel mirrors skelScript: the clustered listing of /etc/skel, then the
// template startup files themselves.
func nativeSkel(ctx context.Context) (string, error) {
	var b strings.Builder
	b.WriteString("== /etc/skel\n")
	names := newNameCache()
	for _, row := range listingRows("/etc/skel/", 100, names) {
		b.WriteString(row)
		b.WriteByte('\n')
	}
	b.WriteString(readSections([]string{
		"/etc/skel/.bashrc",
		"/etc/skel/.profile",
		"/etc/skel/.bash_profile",
		"/etc/skel/.bash_login",
		"/etc/skel/.bash_logout",
		"/etc/skel/.zshrc",
	}, nil))
	return b.String(), nil
}

// generatorDirs is the same directory word list generatorsScript walks; on
// usrmerge systems /lib and /usr/lib are one directory, so the walk dedupes by
// resolved path exactly like the script's readlink -f.
var generatorDirs = []string{
	"/etc/systemd/system-generators",
	"/run/systemd/system-generators",
	"/usr/local/lib/systemd/system-generators",
	"/usr/lib/systemd/system-generators",
	"/lib/systemd/system-generators",
	"/etc/systemd/user-generators",
	"/run/systemd/user-generators",
	"/usr/local/lib/systemd/user-generators",
	"/usr/lib/systemd/user-generators",
	"/root/.local/share/systemd/user-generators",
	"/home/*/.local/share/systemd/user-generators",
}

// nativeGenerators mirrors generatorsScript: one clustered listing section per
// unique generator directory.
func nativeGenerators(ctx context.Context) (string, error) {
	var b strings.Builder
	seen := map[string]bool{}
	names := newNameCache()
	for _, dir := range expandDirs(generatorDirs) {
		resolved, err := filepath.EvalSymlinks(dir)
		if err != nil {
			resolved = dir
		}
		if seen[resolved] {
			continue
		}
		seen[resolved] = true
		listingSection(&b, dir, 100, names)
	}
	return b.String(), nil
}

// udevExecRe is the udev rules' external-program keys: the same expression the
// script greps and the rule grades.
var udevExecRe = regexp.MustCompile(`(RUN|PROGRAM|IMPORT)(\+=|\{|=)`)

// nativeUdev mirrors udevScript: per writable layer a clustered listing then
// the assignment keys that reference external programs, capped like the
// script's head.
func nativeUdev(ctx context.Context) (string, error) {
	var b strings.Builder
	names := newNameCache()
	for _, dir := range []string{"/etc/udev/rules.d", "/run/udev/rules.d"} {
		listingSection(&b, dir, 40, names)
		for _, hit := range grepWalk(ctx, dir, grepOptions{pattern: udevExecRe, maxHits: 100}) {
			b.WriteString(hit)
			b.WriteByte('\n')
		}
	}
	return b.String(), nil
}

// pthDirs is the site-packages word list pthScript walks.
var pthDirs = []string{
	"/usr/lib/python3*/dist-packages",
	"/usr/lib/python3*/site-packages",
	"/usr/local/lib/python3*/dist-packages",
	"/usr/local/lib/python3*/site-packages",
}

// pthImportRe anchors ^import the way the script's grep does.
var pthImportRe = regexp.MustCompile(`^import`)

// nativePth mirrors pthScript: import lines in .pth files across every python
// package directory, setuptools' two legitimate precedence files excluded.
func nativePth(ctx context.Context) (string, error) {
	var b strings.Builder
	for _, dir := range expandDirs(pthDirs) {
		for _, hit := range grepWalk(ctx, dir, grepOptions{
			pattern:  pthImportRe,
			includes: []string{"*.pth"},
			excludes: []string{"distutils-precedence.pth", "_distutils_system_mod.pth"},
		}) {
			b.WriteString(hit)
			b.WriteByte('\n')
		}
	}
	return b.String(), nil
}
