package audit

// A web root is an application tree the web server executes. A script that
// appeared after the artifact is a runtime object even when its name is not a
// known webshell signature; the graph is root -> script -> origin.

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"karma/internal/trust"
)

// WebFile is one executable or script file under a web root.
type WebFile struct {
	Path  string
	Root  string
	Facts trust.Facts
}

// WebState is the web-root provenance graph.
type WebState struct {
	Roots []string
	Files []WebFile
}

var webRoots = []string{
	"/var/www", "/srv/www", "/usr/share/nginx/html", "/var/lib/nginx/html",
}

var webSkipDirs = []string{".git", "node_modules", "vendor", "cache", "logs", "data"}

const (
	webFileLimit = 20000
	webDepth     = 6
)

var webScriptSuffixes = []string{
	".php", ".php3", ".php4", ".php5", ".phtml", ".jsp", ".jspx",
	".py", ".pl", ".rb", ".sh", ".cgi", ".asp", ".aspx",
}

func collectWeb(ctx context.Context, snapshot *Snapshot, facts func(string) trust.Facts, prefetch func([]string)) []string {
	state := &snapshot.Web
	var gaps []string
	visited := 0
	for _, root := range webRoots {
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		state.Roots = append(state.Roots, root)
		err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if ctx.Err() != nil {
				return filepath.SkipAll
			}
			if visited > webFileLimit {
				gaps = append(gaps, fmt.Sprintf("web sweep stopped at %d entries", webFileLimit))
				return filepath.SkipAll
			}
			visited++
			if entry.IsDir() {
				if path != root && strings.Count(strings.TrimPrefix(path, root), "/") >= webDepth {
					return filepath.SkipDir
				}
				for _, skip := range webSkipDirs {
					if entry.Name() == skip {
						return filepath.SkipDir
					}
				}
				return nil
			}
			if entry.Type()&fs.ModeSymlink != 0 || !entry.Type().IsRegular() {
				return nil
			}
			if !webScript(path, entry) {
				return nil
			}
			state.Files = append(state.Files, WebFile{Path: path, Root: root})
			return nil
		})
		if err != nil {
			gaps = append(gaps, "web sweep of "+root+": "+err.Error())
		}
	}
	if len(state.Files) == 0 {
		return gaps
	}
	paths := make([]string, 0, len(state.Files))
	for _, file := range state.Files {
		paths = append(paths, file.Path)
	}
	prefetch(paths)
	for index := range state.Files {
		state.Files[index].Facts = facts(state.Files[index].Path)
		remember(snapshot, state.Files[index].Path, state.Files[index].Facts)
	}
	sort.Slice(state.Files, func(i, j int) bool { return state.Files[i].Path < state.Files[j].Path })
	return gaps
}

func webScript(path string, entry fs.DirEntry) bool {
	info, err := entry.Info()
	if err != nil {
		return false
	}
	if info.Mode().Perm()&0o111 != 0 {
		return true
	}
	lower := strings.ToLower(path)
	for _, suffix := range webScriptSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func judgeWeb(snapshot *Snapshot, a *assessor, filter Filter, add func(Finding)) []string {
	state := &snapshot.Web
	if len(state.Files) == 0 {
		return nil
	}
	var coverage []string
	shown := 0
	for _, file := range state.Files {
		if !pathInScope(file.Path, filter) {
			continue
		}
		if shown >= 100 {
			coverage = append(coverage, fmt.Sprintf("%d more web script(s) than the report shows", len(state.Files)-shown))
			break
		}
		story := a.read(file.Facts, false)
		if story.origin != Runtime && story.origin != Modified {
			continue
		}
		shown++
		severity := severityFor(story.origin, ServiceAsset)
		evidence := []string{
			fmt.Sprintf("web root %s", file.Root),
			fmt.Sprintf("origin %s (%s)", story.origin, story.why),
		}
		evidence = append(evidence, story.evidence...)
		add(Finding{
			Class: "web-script", Severity: severity,
			Title: "web-root script introduced after the artifact",
			Path:  file.Path, Origin: story.origin, Reach: ServiceAsset,
			Detail:   "the web server executes this tree",
			Evidence: evidence,
			Trace:    steps("web root "+file.Root, file.Path, story.origin.String()),
		})
	}
	return coverage
}

func webGraph(snapshot *Snapshot) *Profile {
	graph := domainRoot("domain", "web", "web-root script provenance", NoAsset)
	for _, dir := range snapshot.Web.Roots {
		node := graph.Node("dir", dir, dir, dir, Unknown, ServiceAsset, "web root")
		graph.link(graph.root, node.ID, "contains", "web", "high", "")
	}
	a := newAssessor(snapshot)
	for _, file := range snapshot.Web.Files {
		story := a.read(file.Facts, false)
		node := graph.Node("file", file.Path, file.Path, file.Path, story.origin, ServiceAsset, story.why)
		graph.link(nodeKey("dir", file.Root), node.ID, "contains", "tree", "high", "")
	}
	return graph.Profile("domain", snapshot)
}
