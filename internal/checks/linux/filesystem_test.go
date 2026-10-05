package linux

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The ssh tier and the local tier must cover the same roots: the generated find
// carries the check's filesystem vocabulary into its awk filter, and the check
// hands that same list to the in-process walk.
func TestPrivilegeFindCoversTheVocabulary(t *testing.T) {
	find := privilegeFind("-4000")
	for _, fsType := range privFsTypes {
		if !strings.Contains(find, fsType) {
			t.Errorf("the generated find is missing the %s mount type:\n%s", fsType, find)
		}
	}
	for _, want := range []string{"/proc/self/mounts", `find "$root" -xdev -perm -4000 -type f`} {
		if !strings.Contains(find, want) {
			t.Errorf("the generated find should contain %q:\n%s", want, find)
		}
	}
	if sgid := privilegeFind("-2000"); !strings.Contains(sgid, `find "$root" -xdev -perm -2000 -type f`) {
		t.Errorf("the sgid find should carry its own bit:\n%s", sgid)
	}
}

// The ssh tier is a shell pipeline: a root list out of the mount table feeding
// one find per root. A test host cannot mount a data disk, so the pipeline runs
// here against a fixture table over a temp directory that plays the part — one
// root plain, one whose name carries the kernel's \040 escape for a blank.
func TestPrivilegeFindWalksEveryRoot(t *testing.T) {
	if _, err := exec.LookPath("find"); err != nil {
		t.Skip("no find on this host")
	}
	root := t.TempDir()
	spaced := filepath.Join(root, "space dir")
	if err := os.Mkdir(spaced, 0o755); err != nil {
		t.Fatal(err)
	}
	// The owner-execute bit stands in for setuid: some filesystems (macOS temp
	// volumes) strip the special bits, and the filter is the same bit test.
	plain := filepath.Join(root, "plain")
	marked := filepath.Join(spaced, "marked")
	if err := os.WriteFile(plain, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marked, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	table := filepath.Join(root, "mounts")
	rows := "tmpfs " + root + " tmpfs rw,nosuid 0 0\n" +
		"proc /proc proc rw 0 0\n" + // not a storage type: left out
		"tmpfs " + strings.ReplaceAll(spaced, " ", `\040`) + " tmpfs rw 0 0\n"
	if err := os.WriteFile(table, []byte(rows), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("/bin/sh", "-c", privilegeFindAt("-100", table)).Output()
	if err != nil {
		t.Fatalf("the pipeline failed: %v (output %q)", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if !slices.Contains(lines, marked) {
		t.Fatalf("the escaped root's entry is missing from %q", lines)
	}
	for _, line := range lines {
		if line == plain || !strings.HasPrefix(line, root) {
			t.Fatalf("the pipeline listed %q, want only entries under %s", line, root)
		}
	}
}
