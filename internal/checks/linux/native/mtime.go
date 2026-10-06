// native tier of the mtime subcommand: the same metadata stream the find
// tier collects, walked in process — one section per directory, mtime, ctime,
// target-local date and time, bytes, path, tab-separated.

package native

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"

	"karma/internal/localfs"
	"karma/internal/section"
)

// Hunt renders one directory's rows in findPrintf shape: epoch mtime,
// epoch ctime, date, clock with fraction, bytes, path — the exact fields
// cluster.ParseFindRow reads. pruneDirs are the virtual filesystems to stay out
// of, the same list the find tier prunes by path.
func Hunt(dirs, pruneDirs []string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var b strings.Builder
		for _, dir := range dirs {
			b.WriteString(section.Line(dir))
			err := localfs.WalkTree(ctx, dir, 0, true, func(path string, _ os.FileInfo) bool {
				return slices.Contains(pruneDirs, path)
			}, func(path string, info os.FileInfo) bool {
				if !info.Mode().IsRegular() {
					return true
				}
				st := localfs.StatOf(info)
				fmt.Fprintf(&b, "%s\t%s\t%s\t%02d:%02d:%02d.%09d\t%d\t%s\n",
					localfs.EpochFrac(st.Mtime), localfs.EpochFrac(st.Ctime),
					st.Mtime.Format("2006-01-02"),
					st.Mtime.Hour(), st.Mtime.Minute(), st.Mtime.Second(), st.Mtime.Nanosecond(),
					info.Size(), path)
				return true
			})
			if err != nil {
				return b.String(), err
			}
		}
		return b.String(), nil
	}
}
