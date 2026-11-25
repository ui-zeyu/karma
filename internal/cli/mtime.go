// mtime: one directory tree by change time. It is the view an operator uses
// when the artifact boundary is unknown and a recent write is the only lead.

package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"karma/internal/model"
	"karma/internal/script"
	"karma/internal/session"
)

type mtimeRow struct {
	seconds int64
	mode    string
	size    int64
	path    string
}

func newMtimeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mtime DIR...",
		Short: "List a tree by change time",
		Args:  atLeastOneArg("mtime needs at least one directory: karma local mtime DIR..."),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMtime(cmd.Context(), cmd.OutOrStdout(), session.LocalTransport{}, args)
		},
	}
}

func runMtime(ctx context.Context, w io.Writer, transport session.Transport, dirs []string) error {
	if len(dirs) == 0 {
		return fmt.Errorf("mtime needs at least one directory")
	}
	rows, err := collectMtime(ctx, transport, dirs)
	if err != nil {
		return err
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].seconds != rows[j].seconds {
			return rows[i].seconds > rows[j].seconds
		}
		return rows[i].path < rows[j].path
	})
	limit := len(rows)
	if limit > 5000 {
		limit = 5000
	}
	for _, row := range rows[:limit] {
		fmt.Fprintf(w, "%s  %s  %8d  %s\n",
			time.Unix(row.seconds, 0).Format(stampLayout), row.mode, row.size, row.path)
	}
	if limit < len(rows) {
		fmt.Fprintf(w, "... %d more rows\n", len(rows)-limit)
	}
	return nil
}

const stampLayout = "2006-01-02 15:04:05"

func collectMtime(ctx context.Context, transport session.Transport, dirs []string) ([]mtimeRow, error) {
	if _, local := transport.(session.LocalTransport); local {
		return localMtime(ctx, dirs)
	}
	ctx, cancel := session.Within(ctx, 60*time.Second)
	defer cancel()
	sess, err := transport.Open(ctx)
	if err != nil {
		return nil, failf(ExitEnvironment, "connection failed: %v", err)
	}
	defer sess.Close()
	var commands []string
	for _, dir := range dirs {
		commands = append(commands, "find "+script.Quote(dir)+" -xdev -printf '%T@ %M %s %p\\n' 2>/dev/null")
	}
	result := sess.Run(ctx, model.Call{Inv: model.Shell{Script: strings.Join(commands, "\n")}})
	if result.Verdict != model.VerdictAnswered {
		return nil, failf(ExitEnvironment, "%s", commandFailure(result))
	}
	return parseMtime(strings.NewReader(result.Stdout)), nil
}

func localMtime(ctx context.Context, dirs []string) ([]mtimeRow, error) {
	var rows []mtimeRow
	for _, root := range dirs {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil || ctx.Err() != nil {
				return nil
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
			rows = append(rows, mtimeRow{
				seconds: info.ModTime().Unix(),
				mode:    info.Mode().String(),
				size:    info.Size(),
				path:    path,
			})
			return nil
		})
		if err != nil {
			return nil, readError("mtime", root, err)
		}
	}
	return rows, nil
}

func parseMtime(reader io.Reader) []mtimeRow {
	var rows []mtimeRow
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		fields := strings.SplitN(scanner.Text(), " ", 4)
		if len(fields) != 4 {
			continue
		}
		seconds, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			continue
		}
		size, _ := strconv.ParseInt(fields[2], 10, 64)
		rows = append(rows, mtimeRow{seconds: int64(seconds), mode: fields[1], size: size, path: fields[3]})
	}
	return rows
}
