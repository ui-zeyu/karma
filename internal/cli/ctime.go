// ctime: one directory tree by inode change time. It is the view an operator
// uses when the artifact boundary is unknown and a recent change is the lead;
// mtime is user-settable, ctime is not.

package cli

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"karma/internal/trust"
)

const (
	ctimeLimit  = 5000
	stampLayout = "2006-01-02 15:04:05"
)

type ctimeRow struct {
	seconds int64
	mode    string
	size    int64
	path    string
}

// ctimeHeap keeps the newest rows: the root is the worst row kept, so a scan
// costs one heap operation per entry instead of collecting the whole tree.
type ctimeHeap []ctimeRow

func (h ctimeHeap) Len() int { return len(h) }
func (h ctimeHeap) Less(i, j int) bool {
	if h[i].seconds != h[j].seconds {
		return h[i].seconds < h[j].seconds
	}
	return h[i].path > h[j].path
}
func (h ctimeHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *ctimeHeap) Push(value any) {
	*h = append(*h, value.(ctimeRow))
}
func (h *ctimeHeap) Pop() any {
	old := *h
	row := old[len(old)-1]
	*h = old[:len(old)-1]
	return row
}

func newCtimeCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "ctime DIR...",
		Short:   "List a tree by inode change time",
		Args:    atLeastOneArg("ctime needs at least one directory: karma ctime DIR..."),
		Example: "karma ctime /etc /var/www",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCtime(cmd.Context(), cmd.OutOrStdout(), args)
		},
	}
}

func runCtime(ctx context.Context, w io.Writer, dirs []string) error {
	kept := &ctimeHeap{}
	heap.Init(kept)
	total := 0
	err := walkCtime(ctx, dirs, func(row ctimeRow) {
		total++
		if kept.Len() < ctimeLimit {
			heap.Push(kept, row)
			return
		}
		if newer(row, (*kept)[0]) {
			(*kept)[0] = row
			heap.Fix(kept, 0)
		}
	})
	if err != nil {
		return err
	}
	rows := make([]ctimeRow, kept.Len())
	for index := range rows {
		rows[index] = heap.Pop(kept).(ctimeRow)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].seconds != rows[j].seconds {
			return rows[i].seconds > rows[j].seconds
		}
		return rows[i].path < rows[j].path
	})
	for _, row := range rows {
		fmt.Fprintf(w, "%s  %s  %8d  %s\n",
			time.Unix(row.seconds, 0).Format(stampLayout), row.mode, row.size, row.path)
	}
	if total > len(rows) {
		fmt.Fprintf(w, "... %d more rows\n", total-len(rows))
	}
	return nil
}

func newer(left, right ctimeRow) bool {
	if left.seconds != right.seconds {
		return left.seconds > right.seconds
	}
	return left.path < right.path
}

func walkCtime(ctx context.Context, dirs []string, visit func(ctimeRow)) error {
	for _, root := range dirs {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.IsDir() {
				switch path {
				case "/proc", "/sys", "/dev":
					return filepath.SkipDir
				}
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return nil
			}
			visit(ctimeRow{
				seconds: trust.CTime(info),
				mode:    info.Mode().String(),
				size:    info.Size(),
				path:    path,
			})
			return nil
		})
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return readError("ctime", root, err)
		}
	}
	return nil
}
