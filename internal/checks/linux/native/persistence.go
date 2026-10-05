// native tiers of the persistence checks: cron surfaces, boot scripts,
// startup files, skel listings, generators, udev rules, motd, and .pth.

package native

import (
	"context"
	"karma/internal/localfs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Cron mirrors the check's cronScript: the crontab files and spool layers it
// hands in, then the invoking user's own crontab.
func Cron(paths []string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		body := localfs.ReadSections(paths, nil)
		return body + "== crontab -l\n" + runHost(ctx, []string{"crontab", "-l"}, false).out, nil
	}
}

// LdPreload reads the preload list bare, exactly like the cat tier: a
// `== path` section title would run the entry rule (titles meet the rules
// too) and flag the file's mere existence.
func LdPreload(ctx context.Context) (string, error) {
	body, err := os.ReadFile("/etc/ld.so.preload")
	if err != nil {
		return "", nil
	}
	return string(body), nil
}

// Skel mirrors the check's skelScript: the clustered listing of the template
// directory, then the template startup files themselves.
func Skel(dir string, head int, templates []string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var b strings.Builder
		b.WriteString(localfs.ListingSection(dir, head, localfs.NewNameCache()))
		b.WriteString(localfs.ReadSections(templates, nil))
		return b.String(), nil
	}
}

// Generators mirrors generatorsScript: one clustered listing section per
// unique generator directory, each capped at head like the script's find.
func Generators(dirs []string, head int) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var b strings.Builder
		seen := map[string]bool{}
		names := localfs.NewNameCache()
		for _, dir := range localfs.ExpandDirs(dirs) {
			resolved, err := filepath.EvalSymlinks(dir)
			if err != nil {
				resolved = dir
			}
			if seen[resolved] {
				continue
			}
			seen[resolved] = true
			b.WriteString(localfs.ListingSection(dir, head, names))
		}
		return b.String(), nil
	}
}

// Udev mirrors the check's udevScript: per writable layer it hands in, a
// clustered listing capped at head and then the assignment keys that reference
// external programs, capped at maxHits like the script's head.
func Udev(dirs []string, head, maxHits int, pattern *regexp.Regexp) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var b strings.Builder
		names := localfs.NewNameCache()
		for _, dir := range dirs {
			b.WriteString(localfs.ListingSection(dir, head, names))
			for _, hit := range localfs.GrepWalk(ctx, dir, localfs.GrepScan{Pattern: pattern, MaxHits: maxHits}) {
				b.WriteString(hit)
				b.WriteByte('\n')
			}
		}
		return b.String(), nil
	}
}

// Pth mirrors the check's pthScript: import lines in the .pth files across every
// python package directory it hands in, setuptools' two legitimate precedence
// files excluded.
func Pth(dirs []string, include string, pattern *regexp.Regexp, excludes []string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var b strings.Builder
		for _, dir := range localfs.ExpandDirs(dirs) {
			for _, hit := range localfs.GrepWalk(ctx, dir, localfs.GrepScan{
				Pattern:  pattern,
				Includes: []string{include},
				Excludes: excludes,
			}) {
				b.WriteString(hit)
				b.WriteByte('\n')
			}
		}
		return b.String(), nil
	}
}
