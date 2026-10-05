// native tier of the mtime subcommand: the same metadata stream the find
// tier collects, walked in process — one section per directory, mtime, ctime,
// target-local date and time, bytes, path, tab-separated.

package linux

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// huntPruneDir mirrors the script's huntPrune names: the virtual filesystems
// a sweep from / must not descend into, decided per directory.
func huntPruneDir(path string, _ os.FileInfo) bool {
	return path == "/proc" || path == "/sys" || path == "/dev"
}

// nativeHunt renders one directory's rows in findPrintf shape: epoch mtime,
// epoch ctime, date, clock with fraction, bytes, path — the exact fields
// cluster.ParseFindRow reads.
func nativeHunt(dirs []string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var b strings.Builder
		for _, dir := range dirs {
			fmt.Fprintf(&b, "== %s\n", dir)
			err := walkTree(ctx, dir, 0, true, huntPruneDir, func(path string, info os.FileInfo) bool {
				if !info.Mode().IsRegular() {
					return true
				}
				st := statOf(info)
				fmt.Fprintf(&b, "%s\t%s\t%s\t%02d:%02d:%02d.%09d\t%d\t%s\n",
					epochFrac(st.mtime), epochFrac(st.ctime),
					st.mtime.Format("2006-01-02"),
					st.mtime.Hour(), st.mtime.Minute(), st.mtime.Second(), st.mtime.Nanosecond(),
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
