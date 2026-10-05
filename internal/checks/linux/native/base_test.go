package native

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestVerifyChangedParsesMd5Flag(t *testing.T) {
	out := "??5?????? c /etc/passwd\n c /etc/shadow\n..5?????? c /usr/bin/sudo\n"
	got := verifyChanged(out)
	want := []string{"/etc/passwd", "/usr/bin/sudo"}
	if !slices.Equal(got, want) {
		t.Fatalf("verifyChanged = %v, want %v", got, want)
	}
}

func TestNativeSuidScanFiltersModeBit(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	marked := filepath.Join(dir, "marked")
	if err := os.WriteFile(plain, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marked, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The owner-execute bit stands in for the setuid/setgid bits the callers
	// pass: some filesystems (macOS temp volumes) strip the special bits, and
	// the filter is the same bit test either way.
	lists, caps, err := scanPrivFiles(context.Background(), []string{dir}, 0o100)
	if err != nil {
		t.Fatal(err)
	}
	if len(lists) != 1 {
		t.Fatalf("scan returned %d bit lists, want 1", len(lists))
	}
	if !slices.Contains(lists[0], marked) || slices.Contains(lists[0], plain) {
		t.Fatalf("mode-bit scan window wrong: %v", lists[0])
	}
	// the same pass reads capabilities; a plain temp file carries none
	if len(caps) != 0 {
		t.Fatalf("capability rows on files without capabilities: %v", caps)
	}
}

func TestNativeMinerPsFilter(t *testing.T) {
	now := time.Now()
	snap := processSnapshot{
		entries: []procEntry{
			{pid: 1, user: "root", args: "xmrig --donate", state: 'S', numThreads: 1},
			{pid: 2, user: "user", args: "grep xmrig", state: 'S', numThreads: 1},
			{pid: 3, user: "user", args: "stratum+tcp://pool", state: 'S', numThreads: 1},
			{pid: 4, user: "user", args: "bash", state: 'S', numThreads: 1},
		},
		boot:     now.Add(-time.Hour),
		uptime:   3600,
		memTotal: 1 << 30,
		ok:       true,
		complete: true,
	}
	var b strings.Builder
	for _, line := range minerPsLines(snap, now, regexp.MustCompile(`\bxmrig\b|stratum\+?(tcp|ssl):`)) {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	body := b.String()
	if !strings.Contains(body, "xmrig --donate") || !strings.Contains(body, "stratum+tcp") {
		t.Fatalf("miner ps window lost hits:\n%s", body)
	}
	if strings.Contains(body, "grep") || strings.Contains(body, "bash") {
		t.Fatalf("miner ps window kept noise:\n%s", body)
	}
}

// The kernel stores a priority in front of every ring-buffer line; dmesg
// prints the line without it.
func TestStripSyslogPriority(t *testing.T) {
	body := "<6>[    0.000000] Linux version 7.0.0\n<4>[   12.5] audit: denied\n" +
		"[    9.9] already bare\n<5>no bracket close\nnot <6> a prefix\n"
	want := "[    0.000000] Linux version 7.0.0\n[   12.5] audit: denied\n" +
		"[    9.9] already bare\nno bracket close\nnot <6> a prefix\n"
	if got := stripSyslogPriority(body); got != want {
		t.Errorf("stripSyslogPriority = %q, want %q", got, want)
	}
	if got := stripSyslogPriority("plain\n"); got != "plain\n" {
		t.Errorf("plain body changed: %q", got)
	}
}

func TestLsmodRows(t *testing.T) {
	data := "udp_diag 12288 0 - Live 0x0000000000000000\n" +
		"inet_diag 24576 2 tcp_diag,udp_diag Live 0x0000000000000000\n" +
		"broken\n"
	want := "Module                  Size  Used by\n" +
		"udp_diag               12288  0\n" +
		"inet_diag              24576  2 tcp_diag,udp_diag\n"
	if got := lsmodRows(data); got != want {
		t.Errorf("lsmodRows:\n%q\nwant:\n%q", got, want)
	}
}
