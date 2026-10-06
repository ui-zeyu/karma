// The pstree tier: the process tree from ppid links, drawn with ASCII
// connectors, over the same snapshot proctable.go provides.

package native

import (
	"context"
	"fmt"
	"strings"

	"karma/internal/model"
)

// Pstree renders the process tree from ppid links, pstree -ap's
// evidence in ASCII connectors.
func Pstree(ctx context.Context) (string, error) {
	snap := procSnapshot(ctx)
	if !snap.ok {
		return "", model.ErrTierUnavailable
	}
	return renderPstree(snap.entries), snap.cutReason(ctx)
}

// renderPstree prints the forest: every process whose parent is absent (pid
// 1, kernel threads) starts a root; children follow under ASCII connectors,
// args appended when the process has a command line.
func renderPstree(entries []procEntry) string {
	children := map[int][]procEntry{}
	byPid := map[int]bool{}
	for _, e := range entries {
		byPid[e.pid] = true
		children[e.ppid] = append(children[e.ppid], e)
	}
	var roots []procEntry
	for _, e := range entries {
		if !byPid[e.ppid] { // pid 1 and any orphan of a vanished parent
			roots = append(roots, e)
		}
	}
	var b strings.Builder
	var walk func(e procEntry, prefix, connector string, last bool)
	walk = func(e procEntry, prefix, connector string, last bool) {
		b.WriteString(prefix)
		b.WriteString(connector)
		fmt.Fprintf(&b, "%s(%d)", e.comm, e.pid)
		if e.args != "" && !strings.HasPrefix(e.args, "[") {
			b.WriteString(" " + e.args)
		}
		b.WriteByte('\n')
		kidPrefix := prefix
		if connector != "" {
			if last {
				kidPrefix += "  "
			} else {
				kidPrefix += "| "
			}
		}
		for i, kid := range children[e.pid] {
			kidLast := i == len(children[e.pid])-1
			conn := "|-"
			if kidLast {
				conn = "`-"
			}
			walk(kid, kidPrefix, conn, kidLast)
		}
	}
	lastRoot := len(roots) - 1
	for i, root := range roots {
		walk(root, "", "", i == lastRoot)
	}
	return b.String()
}
