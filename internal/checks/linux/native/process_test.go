package native

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// DecodeCapMasks is the /proc/self/status tier's Adapt: set masks gain decoded
// names, zero masks and non-Cap lines stay untouched, and a body with nothing
// to decode returns nil so the raw text is used.
func TestDecodeCapMasks(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string // fragments every decoded line must carry
		same bool     // the body must come back unchanged (nil Shaped)
	}{
		{
			name: "single cap",
			body: "CapInh:\t0000000000000000\nCapEff:\t0000000000000001\n",
			want: []string{"CapEff:\t0000000000000001  = cap_chown"},
		},
		{
			name: "full root mask names the dangerous caps",
			body: "CapEff:\t000001ffffffffff\n",
			want: []string{"cap_sys_admin", "cap_sys_module", "cap_dac_read_search", "cap_sys_ptrace"},
		},
		{
			name: "unknown high bits decode to their number",
			body: "CapBnd: 0000200000000000\n",
			want: []string{"bit45"},
		},
		{
			name: "all zero stays raw",
			body: "CapInh:\t0000000000000000\nCapAmb:\t0000000000000000\n",
			same: true,
		},
		{
			name: "non-cap lines stay raw",
			body: "context: container\nSeccomp:\t2\n",
			same: true,
		},
	}
	for _, tc := range cases {
		shaped := DecodeCapMasks("", tc.body)
		if tc.same {
			if shaped != nil {
				t.Errorf("%s: wanted nil Shaped, got %q", tc.name, shaped.Text)
			}
			continue
		}
		if shaped == nil {
			t.Errorf("%s: wanted decoding, got nil", tc.name)
			continue
		}
		for _, want := range tc.want {
			if !strings.Contains(shaped.Text, want) {
				t.Errorf("%s: decoded text misses %q:\n%s", tc.name, want, shaped.Text)
			}
		}
	}
}

// capBitNames walks the mask lowest bit first; a quick cross-check that bit 21
// is cap_sys_admin and bits past the table fall back to numbers.
func TestCapBitNames(t *testing.T) {
	names := capBitNames(1 << 21)
	if len(names) != 1 || names[0] != "cap_sys_admin" {
		t.Errorf("bit 21 should be cap_sys_admin, got %v", names)
	}
	names = capBitNames(1<<40 | 1<<42)
	if len(names) != 2 || names[0] != "cap_checkpoint_restore" || names[1] != "bit42" {
		t.Errorf("past-table bits should number themselves, got %v", names)
	}
}

// hiddenPidScan.run crosses the kill(0) oracle against the readdir view. The
// oracles are injected with per-pass answers so every race has a case: a
// process that exits between the two passes and a process that appears
// between them are both dropped, and only a PID that stays kernel-alive and
// readdir-absent across both listings is reported.
func TestHiddenPidScan(t *testing.T) {
	cases := []struct {
		name   string
		pidMax int
		euid   int
		kill1  map[int]bool // oracle answers during the brute pass
		kill2  map[int]bool // oracle answers during confirmation (nil: same)
		list1  []int        // readdir view, first listing
		list2  []int        // readdir view, confirmation listing
		want   []string
		ban    []string
	}{
		{
			name: "clean host", pidMax: 100,
			kill1: map[int]bool{1: true, 2: true, 300: true},
			list1: []int{1, 2, 300}, list2: []int{1, 2, 300},
			want: []string{"scan: pid_max=100 scanned=1-100"},
			ban:  []string{"== hidden", "PID "},
		},
		{
			name: "hidden pid survives confirmation", pidMax: 200,
			kill1: map[int]bool{1: true, 2: true, 42: true},
			list1: []int{1, 2}, list2: []int{1, 2},
			want: []string{"== hidden", "PID 42  fd=yes  comm=bash  cmd='/bin/bash -i'"},
		},
		{
			name: "exit between passes is dropped", pidMax: 200,
			kill1: map[int]bool{1: true, 2: true, 42: true},
			kill2: map[int]bool{1: true, 2: true},
			list1: []int{1, 2}, list2: []int{1, 2},
			ban: []string{"PID "},
		},
		{
			name: "appeared between passes is dropped", pidMax: 200,
			kill1: map[int]bool{1: true, 2: true, 42: true},
			list1: []int{1, 2}, list2: []int{1, 2, 42},
			ban: []string{"PID "},
		},
		{
			name: "thread ids count as visible", pidMax: 400,
			kill1: map[int]bool{1: true, 300: true, 301: true},
			list1: []int{1, 300, 301}, list2: []int{1, 300, 301},
			ban: []string{"PID "},
		},
		{
			name: "non-root adds the caveat", pidMax: 100, euid: 1000,
			kill1: map[int]bool{1: true},
			list1: []int{1}, list2: []int{1},
			want: []string{"note: not running as root"},
		},
	}
	for _, tc := range cases {
		listCalls := 0
		scan := hiddenPidScan{
			pidMax:  tc.pidMax,
			scanCap: tc.pidMax,
			euid:    tc.euid,
			kill0: func(pid int) bool {
				if listCalls == 1 {
					return tc.kill1[pid]
				}
				if tc.kill2 != nil {
					return tc.kill2[pid]
				}
				return tc.kill1[pid]
			},
			fdExists: func(pid int) bool { return pid == 42 },
			listPIDs: func() []int {
				listCalls++
				if listCalls == 1 {
					return tc.list1
				}
				return tc.list2
			},
			readFile: func(path string) (string, bool) {
				switch path {
				case "/proc/42/comm":
					return "bash\n", true
				case "/proc/42/cmdline":
					return "/bin/bash\x00-i\x00", true
				}
				return "", false
			},
		}
		text, err := scan.run(context.Background())
		if err != nil {
			t.Fatalf("%s: run returned %v", tc.name, err)
		}
		for _, want := range tc.want {
			if !strings.Contains(text, want) {
				t.Errorf("%s: output misses %q:\n%s", tc.name, want, text)
			}
		}
		for _, ban := range tc.ban {
			if strings.Contains(text, ban) {
				t.Errorf("%s: output must not contain %q:\n%s", tc.name, ban, text)
			}
		}
	}
}

// The brute pass respects the scan cap, which is what bounds the tier's
// runtime on hosts whose pid_max runs into the millions.
func TestHiddenPidScanCap(t *testing.T) {
	maxProbed := 0
	scan := hiddenPidScan{
		pidMax:  1 << 20,
		scanCap: 64,
		kill0: func(pid int) bool {
			if pid > maxProbed {
				maxProbed = pid
			}
			return false
		},
		listPIDs: func() []int { return []int{1} },
	}
	if _, err := scan.run(context.Background()); err != nil {
		t.Fatalf("run returned %v", err)
	}
	if maxProbed != 64 {
		t.Fatalf("the scan should stop at the cap, last probed pid was %d", maxProbed)
	}
}

// A cancelled context stops the sweep and hands back the lines printed so far.
func TestHiddenPidScanCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	scan := hiddenPidScan{
		pidMax: 100, scanCap: 100,
		kill0:    func(int) bool { return false },
		listPIDs: func() []int { return []int{1} },
	}
	text, err := scan.run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("wanted the context error, got %v", err)
	}
	if !strings.Contains(text, "scan: pid_max=100") {
		t.Fatalf("partial output should keep the context line, got %q", text)
	}
}
