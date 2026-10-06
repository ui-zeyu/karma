// native_utmp: the login records straight from the binary accounting files
// (utmp, wtmp, btmp, lastlog). The utilities that read them (w, who, last,
// lastb, lastlog) are dynamically linked on every distro, so on the local
// channel karma parses the files itself and the interposition surface
// disappears with them.

package native

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"karma/internal/localfs"
	"karma/internal/model"
	"karma/internal/textutil"
)

// The glibc utmp record: a fixed 384-byte little-endian layout every Linux
// ABI carries (ut_tv is 32-bit on purpose). Field offsets, not struct
// casting, keep the parse endian-explicit.
const (
	utmpSize    = 384
	utmpLineOff = 8
	utmpLineLen = 32
	utmpIDOff   = 40
	utmpIDLen   = 4
	utmpUserOff = 44
	utmpUserLen = 32
	utmpHostOff = 76
	utmpHostLen = 256
	utmpTimeOff = 340
)

// utmp record types the login views print.
const (
	utBootTime   = 2
	utUserProc   = 7
	utDeadProc   = 8
	utShutdownLn = "~"
)

// lastTimeFmt is last's login timestamp spelling ("Mon Oct  5 09:12").
const lastTimeFmt = "Mon Jan _2 15:04"

// utmpRec is one decoded accounting record.
type utmpRec struct {
	typ  int32
	line string
	id   string
	user string
	host string
	at   time.Time
}

// decodeUtmp decodes one 384-byte record.
func decodeUtmp(rec []byte) utmpRec {
	sec := int32(binary.LittleEndian.Uint32(rec[utmpTimeOff:]))
	return utmpRec{
		typ:  int32(binary.LittleEndian.Uint16(rec[:2])),
		line: textutil.CStr(rec[utmpLineOff : utmpLineOff+utmpLineLen]),
		id:   textutil.CStr(rec[utmpIDOff : utmpIDOff+utmpIDLen]),
		user: textutil.CStr(rec[utmpUserOff : utmpUserOff+utmpUserLen]),
		host: textutil.CStr(rec[utmpHostOff : utmpHostOff+utmpHostLen]),
		at:   time.Unix(int64(sec), 0),
	}
}

// readUtmpRecords reads an accounting file; ok is false when the file is
// absent, the "binary missing" case of the script tier. A truncated tail
// (a crash mid-write) is dropped, whole records survive.
func readUtmpRecords(path string) ([]utmpRec, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var recs []utmpRec
	for off := 0; off+utmpSize <= len(data); off += utmpSize {
		recs = append(recs, decodeUtmp(data[off:off+utmpSize]))
	}
	return recs, true
}

// userRecords selects the interactive sessions from utmp.
func userRecords(recs []utmpRec) []utmpRec {
	var out []utmpRec
	for _, r := range recs {
		if r.typ == utUserProc && r.user != "" {
			out = append(out, r)
		}
	}
	return out
}

// Who mirrors `who`: one row per live session.
func Who(ctx context.Context) (string, error) {
	recs, ok := readUtmpRecords("/var/run/utmp")
	if !ok {
		return "", model.ErrTierUnavailable
	}
	var b strings.Builder
	for _, r := range userRecords(recs) {
		fmt.Fprintf(&b, "%-8s %-12s %s", r.user, r.line, r.at.Format("2006-01-02 15:04"))
		if r.host != "" {
			fmt.Fprintf(&b, " (%s)", r.host)
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// idleFormat renders w's IDLE cell from a terminal's last-activity time.
func idleFormat(d time.Duration) string {
	switch {
	case d < 0:
		return "?"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d:%02d", int(d.Minutes()), int(d.Seconds())%60)
	case d < 24*time.Hour:
		return fmt.Sprintf("%d:%02d", int(d.Hours()), int(d.Minutes())%60)
	default:
		return "old"
	}
}

// W mirrors `w`: the uptime banner, then one row per live session with
// the terminal's idle time and the CPU spent by the processes on it.
func W(ctx context.Context) (string, error) {
	recs, ok := readUtmpRecords("/var/run/utmp")
	if !ok {
		return "", model.ErrTierUnavailable
	}
	snap := procSnapshot(ctx)
	if !snap.ok {
		return "", model.ErrTierUnavailable
	}
	now := time.Now()
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", uptimeBannerLine())
	b.WriteString("USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n")
	for _, r := range userRecords(recs) {
		idle, jcpu, pcpu, what := "?", 0.0, 0.0, "-"
		if info, err := os.Stat("/dev/" + r.line); err == nil {
			idle = idleFormat(now.Sub(localfs.StatOf(info).Atime))
		}
		var fg *procEntry
		for i := range snap.entries {
			e := &snap.entries[i]
			if ttyName(e.ttyNr) != r.line {
				continue
			}
			jcpu += e.cpuSeconds()
			if e.pid == e.tpgid {
				fg = e
			}
		}
		if fg != nil {
			pcpu, what = fg.cpuSeconds(), fg.args
		}
		from := r.host
		if from == "" {
			from = "-"
		}
		fmt.Fprintf(&b, "%-8s %-8s %-16s %-8s %-7s %-7s %-6s %s\n",
			r.user, r.line, from, r.at.Format("15:04"), idle,
			psTimeFormat(jcpu), psTimeFormat(pcpu), what)
	}
	return b.String(), snap.cutReason(ctx)
}

// lastRow is one rendered wtmp session for `last`.
type lastRow struct {
	user, tty, host, login, end, duration string
}

// renderLastRow prints one last row; duration is empty for open rows.
func renderLastRow(b *strings.Builder, r lastRow) {
	fmt.Fprintf(b, "%-8s %-12s %-16s %s", r.user, r.tty, r.host, r.login)
	if r.end != "" {
		fmt.Fprintf(b, " - %s", r.end)
	}
	if r.duration != "" {
		fmt.Fprintf(b, " %s", r.duration)
	}
	b.WriteByte('\n')
}

// lastDuration renders last's "(HH:MM)" / "(D+HH:MM)" run length.
func lastDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	h := int(d.Hours())
	if h >= 24 {
		return fmt.Sprintf("(%d+%02d:%02d)", h/24, h%24, int(d.Minutes())%60)
	}
	return fmt.Sprintf("(%02d:%02d)", h, int(d.Minutes())%60)
}

// lastSessionRows walks wtmp chronologically, pairing logins with logouts by
// ut_id (the terminal slot). An unpaired login prints "still logged in" when
// the session is still open in utmp and "gone - no logout" otherwise — the
// crash signature last reports.
func lastSessionRows(recs []utmpRec, live map[string]bool) []lastRow {
	closed := func(prior utmpRec, end time.Time) lastRow {
		return lastRow{
			user: prior.user, tty: prior.line, host: prior.host,
			login:    prior.at.Format(lastTimeFmt),
			end:      end.Format("15:04"),
			duration: lastDuration(end.Sub(prior.at)),
		}
	}
	var rows []lastRow
	open := map[string]utmpRec{}
	for _, r := range recs {
		switch {
		case r.typ == utBootTime:
			row := lastRow{user: "reboot", tty: "system boot", host: r.host,
				login: r.at.Format(lastTimeFmt)}
			if boot := bootTime(); !boot.IsZero() && r.at.Sub(boot).Abs() < 2*time.Minute {
				row.end = "still running"
			}
			rows = append(rows, row)
		case r.typ == utDeadProc && r.line == utShutdownLn && r.user == "shutdown":
			rows = append(rows, lastRow{user: "shutdown", tty: "system down", host: r.host,
				login: r.at.Format(lastTimeFmt)})
		case r.typ == utUserProc:
			if r.user == "" {
				continue
			}
			if prior, ok := open[r.id]; ok {
				rows = append(rows, lastRow{user: prior.user, tty: prior.line, host: prior.host,
					login: prior.at.Format(lastTimeFmt), end: "gone - no logout"})
			}
			open[r.id] = r
		case r.typ == utDeadProc:
			prior, ok := open[r.id]
			if !ok {
				continue
			}
			delete(open, r.id)
			rows = append(rows, closed(prior, r.at))
		}
	}
	var leftovers []utmpRec
	for _, r := range open {
		leftovers = append(leftovers, r)
	}
	slices.SortFunc(leftovers, func(a, b utmpRec) int { return a.at.Compare(b.at) })
	for _, r := range leftovers {
		end := "gone - no logout"
		if live[r.id] {
			end = "still logged in"
		}
		rows = append(rows, lastRow{user: r.user, tty: r.line, host: r.host,
			login: r.at.Format(lastTimeFmt), end: end})
	}
	return rows
}

// The record files the local utmp family reads: the login records, the failed
// attempts, the live sessions, and wtmpdb's database, which the wtmpdb-aware
// last(1) writes instead of /var/log/wtmp.
const (
	utmpFile = "/var/run/utmp"
	wtmpFile = "/var/log/wtmp"
	btmpFile = "/var/log/btmp"
	wtmpdb   = "/var/log/wtmp.db"
)

// wtmpdbLive reports whether logins are recorded in wtmpdb's database. The
// wtmpdb-aware last(1) then reads the database and /var/log/wtmp stops being
// written, so the binary file still parses — it just no longer holds the live
// sessions, and reporting them would present stale evidence as current.
func wtmpdbLive() bool {
	_, err := os.Stat(wtmpdb)
	return err == nil
}

// Last mirrors `last -n limit`: sessions newest first, the wtmp trailer naming
// where the record begins. A host whose logins live in wtmpdb hands the question
// to its own last(1), which reads the database. The check hands the same limit
// to the script branch, so both channels show the same window.
func Last(limit int) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		if wtmpdbLive() {
			return "", model.ErrTierUnavailable
		}
		recs, ok := readUtmpRecords(wtmpFile)
		if !ok {
			return "", model.ErrTierUnavailable
		}
		live := map[string]bool{}
		if utmp, ok := readUtmpRecords(utmpFile); ok {
			for _, r := range userRecords(utmp) {
				live[r.id] = true
			}
		}
		return lastPanel(lastSessionRows(recs, live), limit, wtmpFile, "wtmp", recs), nil
	}
}

// lastPanel renders a last(1)-shaped table: the rows newest first, capped at
// the limit the script branch is given, closed by the trailer naming where the
// file's records begin. rows is reversed in place, so the caller hands in a
// slice of its own.
func lastPanel(rows []lastRow, limit int, path, label string, recs []utmpRec) string {
	slices.Reverse(rows)
	if len(rows) > limit {
		rows = rows[:limit]
	}
	var b strings.Builder
	for _, row := range rows {
		renderLastRow(&b, row)
	}
	b.WriteString(recordTrailer(path, label, recs))
	return b.String()
}

// firstRecordTime is the oldest surviving record's time, the wtmp trailer.
func firstRecordTime(recs []utmpRec) time.Time {
	if len(recs) == 0 {
		return time.Time{}
	}
	return recs[0].at
}

// recordTrailer is last's closing line: where the records begin. A file with no
// record at all — an untouched btmp — gets the notice the wtmpdb family prints
// instead, since the zero time would otherwise read as a year-1 timestamp.
func recordTrailer(path, label string, recs []utmpRec) string {
	if len(recs) == 0 {
		return path + " has no entries\n"
	}
	return fmt.Sprintf("\n%s begins %s\n", label,
		firstRecordTime(recs).Format("Mon Jan _2 15:04:05 2006"))
}

// Lastb mirrors `lastb -n limit`: every failed attempt, newest first, the same
// limit the script branch is given.
func Lastb(limit int) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		recs, ok := readUtmpRecords(btmpFile)
		if !ok {
			return "", model.ErrTierUnavailable
		}
		rows := make([]lastRow, 0, len(recs))
		for _, r := range recs {
			if r.user == "" {
				continue
			}
			rows = append(rows, lastRow{user: r.user, tty: r.line, host: r.host,
				login: r.at.Format(lastTimeFmt)})
		}
		return lastPanel(rows, limit, btmpFile, "btmp", recs), nil
	}
}

// lastlog's fixed record: 32-bit time, 32-byte line, 256-byte host, indexed
// by uid — a sparse file read at each account's slot.
const (
	lastlogSize    = 292
	lastlogLineOff = 4
	lastlogHostOff = 36
)

// lastlog2DB is where the account records moved on the 26.04 generation of
// Ubuntu and its neighbours (wtmpdb's companion lastlog2).
const lastlog2DB = "/var/lib/lastlog/lastlog2.db"

// Lastlog mirrors `lastlog`: the newest login per account, read from the
// sparse file indexed by uid. Where the records moved to lastlog2's database
// the classic file is only written by legacy paths and falls behind the live
// store, so the panel states the age of what it is showing up front instead of
// leaving the reader to compare two stores.
func Lastlog(ctx context.Context) (string, error) {
	users, err := passwdUsers()
	if err != nil {
		return "", model.ErrTierUnavailable
	}
	data, err := os.ReadFile("/var/log/lastlog")
	if err != nil {
		return "", model.ErrTierUnavailable
	}
	var b strings.Builder
	if _, err := os.Stat(lastlog2DB); err == nil {
		fmt.Fprintf(&b, "note: %s present, /var/log/lastlog is frozen at its last pre-migration write\n", lastlog2DB)
	}
	b.WriteString(lastlogHeaderLine() + "\n")
	for _, u := range users {
		off := u.uid * lastlogSize
		line, host, latest := "", "", lastlogNever
		if off+lastlogSize <= len(data) {
			rec := data[off : off+lastlogSize]
			when := int32(binary.LittleEndian.Uint32(rec[:4]))
			line = textutil.CStr(rec[lastlogLineOff : lastlogLineOff+utmpLineLen])
			host = textutil.CStr(rec[lastlogHostOff : lastlogHostOff+utmpHostLen])
			if when > 0 {
				latest = time.Unix(int64(when), 0).Format(lastlogTimeFormat)
			}
		}
		b.WriteString(lastlogRow(u.name, line, host, latest) + "\n")
	}
	return b.String(), nil
}

// lastlog's columns, taken from the tool this tier replaces: the account in 16
// columns, the port in 8 (a longer line is cut to eight with no marker), and
// the host left-justified in maxIPv6Addrlen = 25 + 1 + IFNAMSIZ columns, which
// starts the timestamps at column 68. The header pads "From" with
// maxIPv6Addrlen-3 spaces where the rows pad the host with maxIPv6Addrlen, so
// "Latest" sits one column right of the column it labels — kept as the tool
// prints it, so a local run and an ssh run of the same host agree. The panel's
// syntax anchors its colors on that header, and its boundary tolerance covers
// the one-column float.
const (
	lastlogHostWidth   = 42
	lastlogHeaderWidth = lastlogHostWidth + 1
	lastlogTimeFormat  = "Mon Jan _2 15:04:05 -0700 2006"
	lastlogNever       = "**Never logged in**"
)

func lastlogHeaderLine() string {
	return fmt.Sprintf("%-16s %-8s %-*s%s", "Username", "Port", lastlogHeaderWidth, "From", "Latest")
}

func lastlogRow(name, line, host, latest string) string {
	return fmt.Sprintf("%-16s %-8.8s %-*s%s", name, line, lastlogHostWidth, host, latest)
}

// passwdUser is one /etc/passwd account slot lastlog needs.
type passwdUser struct {
	name string
	uid  int
}

// passwdUsers lists the accounts lastlog prints, in its order: the row set is
// what getpwent() reports, which on a files-backed NSS is the passwd file's own
// order (so a later account of the same uid gets its own row).
func passwdUsers() ([]passwdUser, error) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, err
	}
	return parsePasswdUsers(string(data)), nil
}

// parsePasswdUsers decodes the passwd table into lastlog's row set.
func parsePasswdUsers(data string) []passwdUser {
	var users []passwdUser
	for line := range strings.SplitSeq(data, "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		users = append(users, passwdUser{name: f[0], uid: uid})
	}
	return users
}
