// native tiers of the persistence checks: cron surfaces, boot scripts,
// startup files, skel listings, generators, udev rules, motd, and .pth.

package native

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Cron mirrors the check's cronScript: the crontab files and spool layers it
// hands in, then the invoking user's own crontab.
func Cron(paths []string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		body := ReadSections(paths, nil)
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
		fmt.Fprintf(&b, "== %s\n", dir)
		names := newNameCache()
		for _, row := range listingRows(dir+"/", head, names) {
			b.WriteString(row)
			b.WriteByte('\n')
		}
		b.WriteString(ReadSections(templates, nil))
		return b.String(), nil
	}
}

// Generators mirrors generatorsScript: one clustered listing section per
// unique generator directory.
func Generators(dirs []string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var b strings.Builder
		seen := map[string]bool{}
		names := newNameCache()
		for _, dir := range expandDirs(dirs) {
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
}

// Udev mirrors the check's udevScript: per writable layer it hands in, a
// clustered listing then the assignment keys that reference external programs,
// capped like the script's head.
func Udev(dirs []string, pattern *regexp.Regexp) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var b strings.Builder
		names := newNameCache()
		for _, dir := range dirs {
			listingSection(&b, dir, 40, names)
			for _, hit := range grepWalk(ctx, dir, GrepScan{Pattern: pattern, MaxHits: 100}) {
				b.WriteString(hit)
				b.WriteByte('\n')
			}
		}
		return b.String(), nil
	}
}

// Pth mirrors the check's pthScript: import lines in .pth files across every
// python package directory it hands in, setuptools' two legitimate precedence
// files excluded.
func Pth(dirs []string, pattern *regexp.Regexp, excludes []string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var b strings.Builder
		for _, dir := range expandDirs(dirs) {
			for _, hit := range grepWalk(ctx, dir, GrepScan{
				Pattern:  pattern,
				Includes: []string{"*.pth"},
				Excludes: excludes,
			}) {
				b.WriteString(hit)
				b.WriteByte('\n')
			}
		}
		return b.String(), nil
	}
}
