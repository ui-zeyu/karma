// Bootstrap's own pieces: the platform gate that keeps a cross-arch upload
// from reaching the target, and the mode split that puts the form after the
// target the way mtime does.

package cli

import "testing"

func TestUnamePlatformMapsTheTargetsKernelAndMachine(t *testing.T) {
	cases := []struct {
		system, machine string
		goos, goarch    string
	}{
		{"Linux", "x86_64", "linux", "amd64"},
		{"Linux", "aarch64", "linux", "arm64"},
		{"Linux", "armv7l", "linux", "arm"},
		{"Linux", "i686", "linux", "386"},
		{"Linux", "riscv64", "linux", "riscv64"},
		{"Darwin", "arm64", "darwin", "arm64"},
		{"FreeBSD", "x86_64", "freebsd", "amd64"},
	}
	for _, c := range cases {
		goos, goarch, err := unamePlatform(c.system, c.machine)
		if err != nil {
			t.Errorf("unamePlatform(%q, %q): %v", c.system, c.machine, err)
			continue
		}
		if goos != c.goos || goarch != c.goarch {
			t.Errorf("unamePlatform(%q, %q) = %s/%s, want %s/%s",
				c.system, c.machine, goos, goarch, c.goos, c.goarch)
		}
	}
}

// An unknown name is an error rather than a guess: a wrong guess means a binary
// that cannot exec on the target.
func TestUnamePlatformRejectsUnknownNames(t *testing.T) {
	for _, c := range [][2]string{{"Plan9", "x86_64"}, {"Linux", "sparc64"}, {"", ""}} {
		if _, _, err := unamePlatform(c[0], c[1]); err == nil {
			t.Errorf("unamePlatform(%q, %q) was accepted", c[0], c[1])
		}
	}
}

func TestBootstrapArgsSplitsTheMode(t *testing.T) {
	if selectors, ok := bootstrapArgs([]string{"bootstrap", "identity", "!kernel"}); !ok || len(selectors) != 2 {
		t.Fatalf("bootstrapArgs = %v, %v", selectors, ok)
	}
	if selectors, ok := bootstrapArgs([]string{"bootstrap"}); !ok || len(selectors) != 0 {
		t.Fatalf("a bare bootstrap form = %v, %v", selectors, ok)
	}
	if _, ok := bootstrapArgs([]string{"identity"}); ok {
		t.Fatal("a selector was taken for the bootstrap form")
	}
	if _, ok := bootstrapArgs(nil); ok {
		t.Fatal("no arguments were taken for the bootstrap form")
	}
}
