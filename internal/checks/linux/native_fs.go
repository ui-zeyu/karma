// native_fs: the disk and mount views from /proc/self/mounts and statfs(2).
// df, mount, and findmnt are dynamically linked binaries; their data sources
// are plain kernel files, so the local channel reads those directly.

package linux

import (
	"context"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"karma/internal/model"
)

// mountRow is one /proc/self/mounts line.
type mountRow struct {
	dev, point, fstype, opts string
}

// parseMounts decodes /proc/self/mounts. The kernel escapes blanks in paths
// as \040-style octal; the escapes are undone so rules match real paths.
func parseMounts(data string) []mountRow {
	var rows []mountRow
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		rows = append(rows, mountRow{
			dev:    unescapeMount(f[0]),
			point:  unescapeMount(f[1]),
			fstype: f[2],
			opts:   unescapeMount(f[3]),
		})
	}
	return rows
}

// unescapeMount turns \0NN octal escapes back into bytes.
func unescapeMount(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+4 <= len(s) {
			if o, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(o))
				i += 4
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// readMounts reads and parses /proc/self/mounts.
func readMounts() ([]mountRow, bool) {
	data, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return nil, false
	}
	return parseMounts(string(data)), true
}

// humanKiB renders df -h's size spelling: one decimal under ten, integer
// above ("4.0K", "9.9M", "99G").
func humanKiB(kib float64) string {
	if kib <= 0 {
		return "0"
	}
	unit := "K"
	for _, u := range []string{"M", "G", "T", "E"} {
		if kib < 1024 {
			break
		}
		kib /= 1024
		unit = u
	}
	if kib < 10 {
		return fmt.Sprintf("%.1f%s", kib, unit)
	}
	return fmt.Sprintf("%d%s", int64(kib+0.5), unit)
}

// dfPercent is df's used share, rounded up the way coreutils does.
func dfPercent(used, total uint64) int {
	if total == 0 {
		return 0
	}
	pct := int(math.Ceil(float64(used) * 100 / float64(total)))
	return min(pct, 100)
}

// nativeDf mirrors `df -h`: every mount with real blocks, the header the df
// lexer anchors on included. The statfs(2) source is per-platform; without it
// the numbers are unavailable and the tier yields to the host's df.
func nativeDf(ctx context.Context) (string, error) {
	rows, ok := readMounts()
	if !ok {
		return "", model.ErrTierUnavailable
	}
	var b strings.Builder
	b.WriteString("Filesystem      Size  Used Avail Use% Mounted on\n")
	for _, m := range rows {
		total, used, avail, ok := statfsBlocks(m.point)
		if !ok || total == 0 {
			continue
		}
		b.WriteString(dfLine(m, total, used, avail) + "\n")
	}
	return b.String(), nil
}

// dfLine renders one df row from the statfs numbers.
func dfLine(m mountRow, total, used, avail uint64) string {
	return fmt.Sprintf("%-16s %5s %5s %5s %3d%% %s",
		m.dev, humanKiB(float64(total)/1024), humanKiB(float64(used)/1024),
		humanKiB(float64(avail)/1024), dfPercent(used, total), m.point)
}

// nativeMount mirrors `mount`'s rows: "dev on point type fstype (opts)".
func nativeMount(ctx context.Context) (string, error) {
	rows, ok := readMounts()
	if !ok {
		return "", model.ErrTierUnavailable
	}
	return renderMountRows(rows), nil
}

// renderMountRows prints the mount(8) view of the kernel's mount table.
func renderMountRows(rows []mountRow) string {
	var b strings.Builder
	for _, m := range rows {
		fmt.Fprintf(&b, "%s on %s type %s (%s)\n", m.dev, m.point, m.fstype, m.opts)
	}
	return b.String()
}

// nativeFindmnt mirrors `findmnt`: the mount tree indented by target depth,
// with the fstype and options columns the mount rules match on.
func nativeFindmnt(ctx context.Context) (string, error) {
	rows, ok := readMounts()
	if !ok {
		return "", model.ErrTierUnavailable
	}
	return renderFindmntRows(rows), nil
}

// renderFindmntRows prints the findmnt(1) view: header, then one indented
// row per mount.
func renderFindmntRows(rows []mountRow) string {
	var b strings.Builder
	b.WriteString("TARGET                SOURCE          FSTYPE         OPTIONS\n")
	for _, m := range rows {
		depth := strings.Count(strings.TrimSuffix(m.point, "/"), "/")
		fmt.Fprintf(&b, "%s%s %s %s (%s)\n",
			strings.Repeat("  ", depth), m.point, m.dev, m.fstype, m.opts)
	}
	return b.String()
}
