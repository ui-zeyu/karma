// tests for the utmp/wtmp/btmp parsers and the login views' row builders.

package linux

import (
	"encoding/binary"
	"os"
	"testing"
	"time"
)

// encodeUtmp builds one 384-byte record the way the C library writes it.
func encodeUtmp(typ int32, line, id, user, host string, at time.Time) []byte {
	rec := make([]byte, utmpSize)
	put := func(off int, s string) {
		copy(rec[off:], s)
	}
	binary.LittleEndian.PutUint16(rec[:2], uint16(typ))
	put(utmpLineOff, line)
	put(utmpIDOff, id)
	put(utmpUserOff, user)
	put(utmpHostOff, host)
	binary.LittleEndian.PutUint32(rec[utmpTimeOff:], uint32(at.Unix()))
	return rec
}

func TestUtmpRoundTrip(t *testing.T) {
	at := time.Date(2026, 10, 5, 9, 12, 0, 0, time.UTC)
	rec := decodeUtmp(encodeUtmp(utUserProc, "pts/0", "s1", "root", "10.0.0.8", at))
	if rec.typ != utUserProc || rec.line != "pts/0" || rec.id != "s1" ||
		rec.user != "root" || rec.host != "10.0.0.8" || !rec.at.Equal(at) {
		t.Fatalf("round trip mismatch: %+v", rec)
	}
}

func TestReadUtmpRecordsDropsTruncatedTail(t *testing.T) {
	full := encodeUtmp(utUserProc, "pts/0", "s1", "root", "", time.Now())
	data := append(append([]byte{}, full...), full[:100]...)
	path := t.TempDir() + "/wtmp"
	if err := writeFile(t, path, data); err != nil {
		t.Fatal(err)
	}
	recs, ok := readUtmpRecords(path)
	if !ok || len(recs) != 1 || recs[0].user != "root" {
		t.Fatalf("truncated tail should leave one whole record: ok=%v recs=%+v", ok, recs)
	}
	if _, ok := readUtmpRecords(t.TempDir() + "/missing"); ok {
		t.Fatal("missing file should report unavailable")
	}
}

// writeFile is the tests' os.WriteFile with failure as error.
func writeFile(t *testing.T, path string, data []byte) error {
	t.Helper()
	return os.WriteFile(path, data, 0o644)
}

func TestLastSessionRows(t *testing.T) {
	login := time.Date(2026, 10, 5, 9, 12, 0, 0, time.UTC)
	logout := login.Add(78 * time.Minute)
	recs := []utmpRec{
		{typ: utUserProc, line: "pts/0", id: "s1", user: "root", host: "10.0.0.8", at: login},
		{typ: utDeadProc, line: "pts/0", id: "s1", user: "", host: "", at: logout},
		{typ: utUserProc, line: "pts/1", id: "s2", user: "alice", host: "10.0.0.9", at: logout},
		{typ: utUserProc, line: "pts/2", id: "s3", user: "bob", host: "", at: login},
		{typ: utBootTime, line: "~", user: "reboot", host: "6.1.0", at: login.Add(-time.Hour)},
	}
	rows := lastSessionRows(recs, map[string]bool{"s2": true})
	var closed, still, gone, boot int
	for _, r := range rows {
		switch {
		case r.tty == "system boot":
			boot++
		case r.end == "still logged in":
			still++
			if r.user != "alice" {
				t.Errorf("still-logged-in row should be alice, got %s", r.user)
			}
		case r.end == "gone - no logout":
			gone++
			if r.user != "bob" {
				t.Errorf("gone row should be bob, got %s", r.user)
			}
		default:
			closed++
			if r.user != "root" || r.end != logout.Format("15:04") || r.duration != "(01:18)" {
				t.Errorf("closed row wrong: %+v", r)
			}
		}
	}
	if closed != 1 || still != 1 || gone != 1 || boot != 1 {
		t.Fatalf("row mix closed=%d still=%d gone=%d boot=%d", closed, still, gone, boot)
	}
}

func TestIdleFormat(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "30s"},
		{5*time.Minute + 7*time.Second, "5:07"},
		{2*time.Hour + 3*time.Minute, "2:03"},
		{3 * 24 * time.Hour, "old"},
	}
	for _, c := range cases {
		if got := idleFormat(c.d); got != c.want {
			t.Errorf("idleFormat(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

func TestParsePasswdUsers(t *testing.T) {
	data := "root:x:0:0:root:/root:/bin/bash\n" +
		"dup:x:0:0:dup:/:/bin/false\n" +
		"alice:x:1000:1000:Alice:/home/alice:/bin/bash\n" +
		"broken:x:uid:0:0::\n"
	users := parsePasswdUsers(data)
	if len(users) != 2 {
		t.Fatalf("users = %+v", users)
	}
	if users[0].name != "root" || users[0].uid != 0 || users[1].name != "alice" || users[1].uid != 1000 {
		t.Fatalf("users = %+v", users)
	}
}

func TestRecordTrailer(t *testing.T) {
	recs := []utmpRec{{typ: utUserProc, line: "pts/0", id: "s1", user: "root",
		at: time.Date(2026, 10, 5, 9, 12, 0, 0, time.UTC)}}
	want := "\nbtmp begins Mon Oct  5 09:12:00 2026\n"
	if got := recordTrailer("/var/log/btmp", "btmp", recs); got != want {
		t.Errorf("trailer = %q, want %q", got, want)
	}
	// an untouched btmp has no records at all: last(1) from the wtmpdb family
	// says so instead of printing a year-1 timestamp
	if got := recordTrailer("/var/log/btmp", "btmp", nil); got != "/var/log/btmp has no entries\n" {
		t.Errorf("empty trailer = %q", got)
	}
}
