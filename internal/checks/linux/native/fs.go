// native_fs: the disk and mount views from /proc/self/mounts and statfs(2).
// df, mount, and findmnt are dynamically linked binaries; their data sources
// are plain kernel files, so the local channel reads those directly.

package native

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"karma/internal/model"
	"karma/internal/shape"
)

// mountRow is one /proc/self/mounts line.
type mountRow struct {
	dev, point, fstype, opts string
}

// parseMounts decodes /proc/self/mounts. The kernel escapes blanks in paths
// as \040-style octal; the escapes are undone so rules match real paths.
func parseMounts(data string) []mountRow {
	var rows []mountRow
	for line := range strings.SplitSeq(string(data), "\n") {
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

// humanKiB renders df -h's size spelling the way coreutils' human_readable
// does with autoscale, base 1024 and ceiling rounding: the value takes the
// largest unit below 1024, one decimal while it is under ten, and is always
// rounded up at the printed precision — so 39.008 GiB prints as 40G and 7.4K
// is the ceiling of 7577 bytes.
func humanKiB(bytes uint64) string {
	if bytes == 0 {
		return "0"
	}
	amt, tenths, rounding := bytes, uint64(0), uint64(0)
	exponent := 0
	for amt >= 1024 && exponent < len(dfUnits)-1 {
		// the rounding flag is a three-state remainder marker: 0 exact,
		// 1/2 rounding down, 3 rounding up
		r10 := amt%1024*10 + tenths
		r2 := r10%1024*2 + rounding>>1
		amt /= 1024
		tenths = r10 / 1024
		switch {
		case r2 < 1024:
			if r2+rounding != 0 {
				rounding = 1
			} else {
				rounding = 0
			}
		case 1024 < r2+rounding:
			rounding = 3
		default:
			rounding = 2
		}
		exponent++
	}
	decimal := false
	tenthsPrinted := uint64(0)
	if amt < 10 {
		if rounding > 0 {
			tenths++
			rounding = 0
			if tenths == 10 {
				amt++
				tenths = 0
			}
		}
		// under ten coreutils keeps the decimal point even at .0 ("4.0K"),
		// and the digit is settled here — the ceiling step below then finds
		// nothing left to round
		decimal, tenthsPrinted = true, tenths
		tenths, rounding = 0, 0
	}
	if tenths+rounding > 0 {
		amt++
		if amt == 1024 && exponent < len(dfUnits)-1 {
			exponent++
			tenthsPrinted = 0
			decimal = true
			amt = 1
		}
	}
	cell := strconv.FormatUint(amt, 10)
	if decimal {
		cell += "." + strconv.FormatUint(tenthsPrinted, 10)
	}
	return cell + dfUnits[exponent]
}

// dfUnits are the suffixes coreutils prints after an autoscaled value.
var dfUnits = []string{"", "K", "M", "G", "T", "P", "E", "Z", "Y", "R", "Q"}

// dfPercent is df's used share, rounded up, over the space a non-root user can
// use (used + available): a filesystem with reserved blocks therefore reads
// higher than used/total, the way df counts it.
func dfPercent(used, avail uint64) int {
	nonroot := used + avail
	if nonroot == 0 {
		return 0
	}
	return int(used*100/nonroot) + btoi(used*100%nonroot != 0)
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// dfDummyTypes are the pseudo filesystems coreutils' df hides unless -a is
// given (ME_DUMMY_0 in mountlist.c); the zero-block test below catches the
// rest, and "none" counts only when the entry is not a bind mount.
//
// devtmpfs is the one type here that reports real blocks: /dev carries the
// device nodes' size, so df hides it by type alone. Checked against GNU df's
// default view (`df` next to `df -a`): every other mount it drops reads zero
// blocks, which the test below already covers.
var dfDummyTypes = map[string]bool{
	"autofs": true, "proc": true, "subfs": true, "debugfs": true, "devpts": true,
	"fusectl": true, "fuse.portal": true, "mqueue": true, "rpc_pipefs": true,
	"sysfs": true, "devfs": true, "kernfs": true, "ignore": true, "devtmpfs": true,
}

// dfDummy reports whether df would leave this mount out of its default view.
func dfDummy(m mountRow) bool {
	if dfDummyTypes[m.fstype] {
		return true
	}
	return m.fstype == "none" && !slices.Contains(strings.Split(m.opts, ","), "bind")
}

// Df mirrors `df -h`: every mount with real blocks, the header the df
// lexer anchors on included. The statfs(2) source is per-platform; without it
// the numbers are unavailable and the tier yields to the host's df.
func Df(ctx context.Context) (string, error) {
	rows, ok := readMounts()
	if !ok {
		return "", model.ErrTierUnavailable
	}
	var b strings.Builder
	b.WriteString("Filesystem      Size  Used Avail Use% Mounted on\n")
	for _, m := range rows {
		if dfDummy(m) {
			continue
		}
		total, used, avail, ok := statfsBlocks(m.point)
		if !ok || total == 0 {
			continue
		}
		b.WriteString(dfLine(m, total, used, avail) + "\n")
	}
	return b.String(), nil
}

// dfLine renders one df row from the statfs numbers. The cell widths are
// fixed, while GNU df widens the filesystem column to its longest name and
// keeps the numeric cells to their own widest values: the same tokens, the
// same rows, and at most a column of padding apart. The df lexer splits on
// blank runs, so either spelling reads the same.
func dfLine(m mountRow, total, used, avail uint64) string {
	return fmt.Sprintf("%-16s %5s %5s %5s %3d%% %s",
		m.dev, humanKiB(total), humanKiB(used), humanKiB(avail), dfPercent(used, avail), m.point)
}

// Mount mirrors `mount`'s rows: "dev on point type fstype (opts)".
func Mount(ctx context.Context) (string, error) {
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

// Findmnt renders findmnt's columns over the kernel's mount table: the target
// indented by its level in the mount tree, then the source, the fstype, and the
// options.
//
// The tree is the one the targets themselves state: a mount hangs under the
// mount on the longest prefix of its target — the mount that covers the
// directory it is mounted in — so a target below a directory nothing mounts
// (/etc/hosts on a host that mounts no /etc) sits one level under the root
// rather than at its path's own depth. The kernel's parent ids live in
// /proc/self/mountinfo, which these readers keep out of: its options field is a
// different string than the one mount prints, and reconciling two readings of
// one table row by row would trade a shape stated from the table for a join
// between two files.
//
// findmnt's box glyphs are not reproduced either: a level is findmnt's own two
// cells of indent, and the rows keep the tokens the check's rules and its table
// lexer read.
func Findmnt(ctx context.Context) (string, error) {
	rows, ok := readMounts()
	if !ok {
		return "", model.ErrTierUnavailable
	}
	return renderFindmntRows(rows), nil
}

// renderFindmntRows prints the findmnt(1) view: header, then one row per mount
// in the mount tree's own order — a mount after the mount that holds it — with
// the target indented by its level, in the one padded table the reading layer's
// shapers use (shape.Table), so the rows line up under the header they name.
// The options keep mount's own parentheses, the way the flat `mount` output
// spells them.
func renderFindmntRows(rows []mountRow) string {
	table := shape.NewTable("TARGET", "SOURCE", "FSTYPE", "OPTIONS")
	for _, mount := range mountOrder(rows) {
		table.Add(strings.Repeat("  ", mount.level)+mount.row.point,
			mount.row.dev, mount.row.fstype, "("+mount.row.opts+")")
	}
	return table.String()
}

// mountTreeNode is one mount where the tree prints it: the row, and its level
// below the root (a root is level 0).
type mountTreeNode struct {
	row   mountRow
	level int
}

// mountOrder orders the mount table as the tree its targets make: a mount hangs
// under the mount covering its target's directory, the mounts no other mount
// covers are the roots, and the walk keeps the table's own order among
// siblings, so a parent is printed before everything under it. A target mounted
// twice — a filesystem mounted over another at the same point — comes out beside
// the mount it covers: both sit in that directory, and only the kernel's parent
// ids tell those two apart.
func mountOrder(rows []mountRow) []mountTreeNode {
	byPoint := make(map[string]int, len(rows))
	for index, row := range rows {
		byPoint[row.point] = index
	}
	children := make([][]int, len(rows))
	var roots []int
	for index, row := range rows {
		parent, ok := coveredBy(byPoint, row.point)
		if !ok {
			roots = append(roots, index)
			continue
		}
		children[parent] = append(children[parent], index)
	}
	var ordered []mountTreeNode
	var walk func(index, level int)
	walk = func(index, level int) {
		ordered = append(ordered, mountTreeNode{row: rows[index], level: level})
		for _, child := range children[index] {
			walk(child, level+1)
		}
	}
	for _, root := range roots {
		walk(root, 0)
	}
	return ordered
}

// coveredBy is the mount covering the directory a mount point sits in: the
// longest prefix of the point that is itself a target in the table, which is
// the deepest mount the point lies under.
func coveredBy(byPoint map[string]int, point string) (int, bool) {
	for parent := mountParentOf(point); parent != ""; parent = mountParentOf(parent) {
		if index, ok := byPoint[parent]; ok {
			return index, true
		}
	}
	return 0, false
}

// mountParentOf is the directory a path sits in: the path without its last
// component, which is the next candidate for the mount covering it. The root,
// and a path that carries no separator, have no directory above them.
func mountParentOf(path string) string {
	if path == "" || path == "/" {
		return ""
	}
	cut := strings.LastIndexByte(path, '/')
	if cut <= 0 {
		return "/"
	}
	return path[:cut]
}
