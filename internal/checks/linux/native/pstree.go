// The pstree tier: the process tree's nodes as fields. The parent link travels
// with each process, so the tree is drawn from the records rather than spelled
// into a command column.

package native

import (
	"context"
	"strconv"

	"karma/internal/model"
)

// PsTreeColumns is the process tree's columns: the node's identity, the parent
// link the tree form nests on, the account, and the command line. The account
// is carried for the rules that read it — a service account running a shell is
// the same finding in a tree as in a table — and the form decides what a node
// draws.
var PsTreeColumns = []string{"PID", "PPID", "USER", "COMMAND"}

// Pstree reads the process tree from the ppid links, pstree's evidence as the
// nodes it is: one record per process, the parent link the form draws the nest
// from. The order is the snapshot's own; the form orders siblings and works out
// the depths, so nothing here spells a ladder.
func Pstree(ctx context.Context) (*model.RecordSet, error) {
	snap := procSnapshot(ctx)
	if !snap.ok {
		return nil, model.ErrTierUnavailable
	}
	rows := make([]model.Record, 0, len(snap.entries))
	for _, entry := range snap.entries {
		rows = append(rows, model.Record{Fields: fields(PsTreeColumns, []string{
			strconv.Itoa(entry.pid), strconv.Itoa(entry.ppid), psUserCell(entry.user), entry.args,
		})})
	}
	return &model.RecordSet{Header: PsTreeColumns, Rows: rows}, snap.cutReason(ctx)
}
