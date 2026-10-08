// native tiers of the persistence checks: cron surfaces, boot scripts,
// startup files, skel listings, generators, udev rules, and motd.

package native

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"

	"karma/internal/localfs"
)

// Crontab reads the invoking user's own crontab, the one schedule surface
// outside the crontab file list.
func Crontab(ctx context.Context) (string, error) {
	return runHost(ctx, []string{"crontab", "-l"}, false).out, nil
}

// LdPreload reads the preload list bare, exactly like the cat tier: a section
// title would run the entry rule (titles meet the rules
// too) and flag the file's mere existence.
func LdPreload(ctx context.Context) (string, error) {
	body, err := localfs.ReadRegular("/etc/ld.so.preload")
	if err != nil {
		return "", nil
	}
	return string(body), nil
}

// GeneratorDirs lists the generator directories, with the usrmerge dedup:
// /lib and /usr/lib are one directory, and reading it twice would double the
// whole section.
func GeneratorDirs(dirs []string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var listed []string
		seen := map[string]bool{}
		for _, dir := range localfs.ExpandDirs(dirs) {
			resolved, err := filepath.EvalSymlinks(dir)
			if err != nil {
				resolved = dir
			}
			if seen[resolved] {
				continue
			}
			seen[resolved] = true
			listed = append(listed, dir)
		}
		return strings.Join(listed, "\n"), nil
	}
}

// UdevDir reads one writable layer: its clustered listing capped at head, then
// the assignment keys that reference external programs, capped at maxHits.
func UdevDir(dir string, head, maxHits int, pattern *regexp.Regexp) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var b strings.Builder
		b.WriteString(localfs.ListingBody(dir, head))
		for _, hit := range localfs.GrepWalk(ctx, dir, localfs.GrepScan{Pattern: pattern, MaxHits: maxHits}) {
			b.WriteString(hit)
			b.WriteByte('\n')
		}
		return b.String(), nil
	}
}
