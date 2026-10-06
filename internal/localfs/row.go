// The ls -l row: one directory entry rendered in the shape the collection
// prints (`script.LSBodyPrintf`), the permission string find's %M spells, the
// epoch fields find's %T@/%C@ spell, and the account-name lookup behind %u/%g.
//
// The rows are the contract with the report: the ls-l pseudo-lexer reads them,
// cluster's listing normalizer lines them up, and the styles/attributes here
// come from lstat in process rather than a hooked libc.

package localfs

import (
	"cmp"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"karma/internal/script"
)

// months is the C-locale month abbreviation table find's %Tb prints under
// LC_ALL=C.
var months = [...]string{
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
}

// permString renders a mode in find %M shape: one type character and three
// rwx triples, with s/S/t/T in the execute positions for the special bits
// (uppercase when the execute bit itself is clear). os.FileMode.String() is not
// this shape: it spells a symlink L, a device D plus its own type character, a
// socket S, and lifts setuid/setgid/sticky to leading flag characters.
func permString(mode os.FileMode) string {
	kind := byte('-')
	switch {
	case mode.IsDir():
		kind = 'd'
	case mode&os.ModeSymlink != 0:
		kind = 'l'
	case mode&os.ModeDevice != 0 && mode&os.ModeCharDevice != 0:
		kind = 'c'
	case mode&os.ModeDevice != 0:
		kind = 'b'
	case mode&os.ModeNamedPipe != 0:
		kind = 'p'
	case mode&os.ModeSocket != 0:
		kind = 's'
	}
	buf := []byte{kind, '-', '-', '-', '-', '-', '-', '-', '-', '-'}
	perm := mode.Perm()
	special := [3]byte{}
	if mode&os.ModeSetuid != 0 {
		special[0] = 's'
	}
	if mode&os.ModeSetgid != 0 {
		special[1] = 's'
	}
	if mode&os.ModeSticky != 0 {
		special[2] = 't'
	}
	execute := [3]bool{perm&0o100 != 0, perm&0o010 != 0, perm&0o001 != 0}
	for triple, mark := range [...]struct{ read, write bool }{
		{perm&0o400 != 0, perm&0o200 != 0},
		{perm&0o040 != 0, perm&0o020 != 0},
		{perm&0o004 != 0, perm&0o002 != 0},
	} {
		base := 1 + triple*3
		if mark.read {
			buf[base] = 'r'
		}
		if mark.write {
			buf[base+1] = 'w'
		}
		switch {
		case execute[triple] && special[triple] != 0:
			buf[base+2] = special[triple]
		case special[triple] != 0:
			buf[base+2] = special[triple] - 32 // S / T
		case execute[triple]:
			buf[base+2] = 'x'
		}
	}
	return string(buf)
}

// NameCache resolves uid/gid numbers to account names with one lookup per id,
// falling back to the number itself the way find's %u/%g do.
type NameCache struct {
	users  map[int]string
	groups map[int]string
}

// NewNameCache returns an empty cache; one cache serves one listing, so a
// directory with a thousand entries of the same owner costs one lookup.
func NewNameCache() *NameCache {
	return &NameCache{users: map[int]string{}, groups: map[int]string{}}
}

// User resolves one uid to its account name, or the number.
func (n *NameCache) User(uid int) string {
	if name, ok := n.users[uid]; ok {
		return name
	}
	name := strconv.Itoa(uid)
	if entry, err := user.LookupId(name); err == nil {
		name = entry.Username
	}
	n.users[uid] = name
	return name
}

// Group resolves one gid to its group name, or the number.
func (n *NameCache) Group(gid int) string {
	if name, ok := n.groups[gid]; ok {
		return name
	}
	name := strconv.Itoa(gid)
	if entry, err := user.LookupGroupId(name); err == nil {
		name = entry.Name
	}
	n.groups[gid] = name
	return name
}

// LsBody renders one entry in script.LSBodyPrintf shape — the row the ls-l
// pseudo-lexer speaks: permissions links owner group size month day clock
// path, a symlink row appending " -> target". find's %l prints the target
// alone, so the reading side (script.linkPath) adds the arrow to a collected
// row; spelling it here keeps the local rows in the same shape.
func LsBody(info os.FileInfo, path string, names *NameCache) string {
	st := StatOf(info)
	body := fmt.Sprintf("%s %d %s %s %d %s %02d %02d:%02d %s",
		permString(info.Mode()), st.Nlink, names.User(st.UID), names.Group(st.GID),
		info.Size(), months[st.Mtime.Month()-1], st.Mtime.Day(),
		st.Mtime.Hour(), st.Mtime.Minute(), path)
	if info.Mode()&os.ModeSymlink != 0 {
		if target, err := os.Readlink(path); err == nil {
			body += " -> " + target
		}
	}
	return body
}

// EpochFrac renders find's epoch-with-fraction field (%T@, %C@): whole seconds
// then a ten-digit fraction, which sort -rn and the cluster parser both read as
// one number. The trailing digit is always zero — find prints ten decimal
// places although timestamps stop at nanoseconds.
func EpochFrac(t time.Time) string {
	return fmt.Sprintf("%d.%010d", t.Unix(), t.Nanosecond()*10)
}

// listedRow is one collection row while it is being ordered: the epoch fields
// as numbers (they are the sort key) and the row text as the collection prints
// it.
type listedRow struct {
	sec  int64  // %T@'s whole seconds
	nsec int    // %T@'s fraction, the ten digits find prints
	text string // the row as the collection prints it
}

// listingOrder is `sort -rn`'s comparison over two collection rows: the epoch
// field first and the whole row after it, every step descending because -r
// reverses the last-resort comparison too. Seconds and nanoseconds are
// compared apart: the printed fraction carries the nanosecond exactly, while
// one float64 would merge neighbouring values near today's epoch.
func listingOrder(a, b listedRow) int {
	return cmp.Or(
		cmp.Compare(b.sec, a.sec),
		cmp.Compare(b.nsec, a.nsec),
		strings.Compare(b.text, a.text),
	)
}

// listingRows is one directory's listing: its entries as
// "%T@\t%C@\t" + ls-l rows, sorted by listingOrder and capped at head. A head
// of zero or less lists every entry. The epoch prefix is the cluster's input;
// RowBody is the half the panels show.
func listingRows(dir string, head int, names *NameCache) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var rows []listedRow
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		st := StatOf(info)
		text := EpochFrac(st.Mtime) + "\t" + EpochFrac(st.Ctime) + "\t" +
			LsBody(info, filepath.Join(dir, entry.Name()), names)
		rows = append(rows, listedRow{sec: st.Mtime.Unix(), nsec: st.Mtime.Nanosecond(), text: text})
	}
	slices.SortFunc(rows, listingOrder)
	if head > 0 && len(rows) > head {
		rows = rows[:head]
	}
	texts := make([]string, len(rows))
	for i, r := range rows {
		texts[i] = r.text
	}
	return texts, nil
}

// rowBody cuts a collection row down to the ls-l body the panels display.
// The two leading fields are the epoch prefix the cluster reads.
func rowBody(row string) string {
	parts := strings.SplitN(row, "\t", 3)
	if len(parts) == 3 {
		return parts[2]
	}
	return row
}

// LsRows renders the `== ls` forensics section for one file list: the ls -l row
// of every path that still exists, in the listing tier's sorted order. The
// attributes come from lstat in process, not from a hooked libc: a setuid bit
// added to an auth binary is the kind of fact an LD_PRELOAD ls would hide. Rows
// are the listing tier's shape (script.LSBodyPrintf) — the same rows every
// other local listing prints — so they differ from GNU ls's column padding, and
// the date is clock-shaped. ls sorts its arguments itself, and a vanished file
// costs only its row (ls reports it on stderr, which the script tier drops).
func LsRows(files []string) string {
	names := NewNameCache()
	var b strings.Builder
	for _, path := range script.LsSorted(files) {
		if info, err := os.Lstat(path); err == nil {
			b.WriteString(LsBody(info, path, names))
			b.WriteByte('\n')
		}
	}
	return b.String()
}
