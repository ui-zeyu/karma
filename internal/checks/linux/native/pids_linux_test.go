//go:build linux

package native

import "testing"

// The local tier sweeps the whole pid space: the scan cap must equal pid_max,
// the kernel's own bound, so no live PID can sit above the sweep. The ssh
// tier's 131072 cap is script-side and does not apply here.
func TestHiddenPidScanCoversPidMax(t *testing.T) {
	scan, err := newHiddenPidScan()
	if err != nil {
		t.Skipf("host has no readable pid_max: %v", err)
	}
	if scan.pidMax < 1 {
		t.Fatalf("pid_max parsed as %d", scan.pidMax)
	}
	if scan.scanCap != scan.pidMax {
		t.Fatalf("scan cap %d must cover pid_max %d", scan.scanCap, scan.pidMax)
	}
}
