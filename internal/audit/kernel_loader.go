package audit

// The dynamic loader search path: ld.so.conf, its includes and the directories it names.

import (
	"context"
	"fmt"
	"karma/internal/trust"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

func collectLoader(ctx context.Context, state *KernelState, snapshot *Snapshot, facts func(string) trust.Facts) []Coverage {
	filter := snapshot.plan.Filter
	var gaps []Coverage
	visited := map[string]bool{}
	var dirs []string
	seenDir := map[string]bool{}

	var walk func(path string, depth int)
	walk = func(path string, depth int) {
		if depth > 4 || visited[path] {
			return
		}
		data, err := readCapped(path, configTextLimit)
		if err != nil {
			return
		}
		visited[path] = true
		state.LoaderConfig = append(state.LoaderConfig, path)
		remember(snapshot, path, facts(path))
		if quote, ok := sourceQuote(path, data); ok {
			quoteInto(state, path, quote)
		}
		includes, parsedDirs := parseLdSoConf(string(data))
		for _, pattern := range includes {
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join("/etc", pattern)
			}
			matches, _ := filepath.Glob(pattern)
			slices.Sort(matches)
			for _, match := range matches {
				walk(match, depth+1)
			}
		}
		for _, dir := range parsedDirs {
			if !seenDir[dir] {
				seenDir[dir] = true
				dirs = append(dirs, dir)
			}
		}
	}

	walk("/etc/ld.so.conf", 0)
	matches, _ := filepath.Glob("/etc/ld.so.conf.d/*.conf")
	slices.Sort(matches)
	for _, match := range matches {
		walk(match, 0)
	}
	slices.Sort(dirs)
	for _, dir := range dirs {
		dirFacts := facts(dir)
		if dirFacts.Kind != trust.Dir {
			continue
		}
		state.LoaderDirs = append(state.LoaderDirs, LoaderDir{Path: dir, Facts: dirFacts})
	}

	var candidates []string
	seenFile := map[string]bool{}
	truncated := false
	for _, dir := range state.LoaderDirs {
		if !filter.touchesPath(dir.Path) {
			continue
		}
		entries, err := os.ReadDir(dir.Path)
		if err != nil {
			gaps = append(gaps, coverageGap("kernel", "dynamic loader search directory is unreadable: "+dir.Path))
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !strings.Contains(name, ".so") {
				continue
			}
			if len(candidates) >= loaderScanLimit {
				truncated = true
				break
			}
			path := filepath.Join(dir.Path, name)
			if seenFile[path] {
				continue
			}
			seenFile[path] = true
			candidates = append(candidates, path)
		}
		if truncated {
			break
		}
	}
	if truncated {
		gaps = append(gaps, Coverage{
			Area: "kernel", Status: CoverageDegraded, Count: loaderScanLimit,
			Detail: fmt.Sprintf("loader search scan stopped at %d files", loaderScanLimit),
		})
	}
	catalog := snapshot.catalog
	if catalog == nil || catalog.Kind() == "none" {
		gaps = append(gaps, coverageGap("kernel", "loader search ownership unavailable: no package database"))
		return gaps
	}
	for _, path := range candidates {
		fileFacts := facts(path)
		if fileFacts.Kind != trust.File || catalog.OwnedPath(path) || catalog.OwnedPath(fileFacts.Real) {
			// A soname is commonly a symlink into a multiarch subdirectory or
			// an alternatives target; the package list records the resolved
			// file, so the resolved spelling answers too.
			continue
		}
		state.LoaderFiles = append(state.LoaderFiles, LoaderFile{Path: path, Facts: fileFacts})
	}
	sort.Slice(state.LoaderFiles, func(i, j int) bool { return state.LoaderFiles[i].Path < state.LoaderFiles[j].Path })
	gaps = append(gaps, Coverage{
		Area: "kernel", Status: CoverageComplete,
		Detail: "loader search compared " + catalog.Kind() + " package file lists",
	})
	return gaps
}

// parseLdSoConf reads one dynamic loader configuration file: include globs
// and the search directories it names. `hwcap` rows are glibc's capability
// annotations, not directories.

func parseLdSoConf(text string) (includes, dirs []string) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if cut := strings.IndexByte(line, '#'); cut >= 0 {
			line = strings.TrimSpace(line[:cut])
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		switch fields[0] {
		case "include":
			if len(fields) >= 2 {
				includes = append(includes, fields[1])
			}
		case "hwcap":
			continue
		default:
			dir := fields[0]
			if !filepath.IsAbs(dir) {
				dir = filepath.Join("/etc", dir)
			}
			dirs = append(dirs, filepath.Clean(dir))
		}
	}
	return includes, dirs
}
