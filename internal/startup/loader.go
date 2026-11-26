package startup

import (
	"path/filepath"
	"strings"
)

// loaderEdges reads /etc/ld.so.preload: the dynamic loader reads this file
// before every program starts, so each entry is a library that runs in every
// process on the host, root's included. The entry is a path or a soname; a
// soname is resolved through the search path and is left dynamic. The cache
// is a self-edge: ldconfig regenerates it, so one rewritten outside the
// package manager is the loader-path decision itself.
func loaderEdges(file File) []rawEdge {
	if filepath.Base(file.Path) == "ld.so.cache" {
		return []rawEdge{selfEdge(file, "ld.so.cache", Session, Subject{Class: AccountAll}, Config)}
	}
	var edges []rawEdge
	for index, raw := range strings.Split(file.Body, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if cut := strings.IndexByte(line, '#'); cut >= 0 {
			line = strings.TrimSpace(line[:cut])
		}
		if line == "" {
			continue
		}
		for _, token := range strings.Fields(line) {
			edges = append(edges, rawEdge{
				surface:   SurfaceLoader,
				phase:     Session,
				subject:   Subject{Class: AccountAll},
				trigger:   file.Path,
				line:      index + 1,
				mechanism: "ld.so.preload",
				target:    token,
				kind:      Preload,
				dynamic:   !filepath.IsAbs(token),
			})
		}
	}
	return edges
}
