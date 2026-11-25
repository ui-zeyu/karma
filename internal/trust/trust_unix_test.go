//go:build !windows

package trust

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyFileAndSymlink(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(file, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	facts := Classify(file, nil)
	if facts.Kind != File || !facts.Executable || facts.Writable || facts.Hidden {
		t.Fatalf("file facts = %+v", facts)
	}
	if facts.PackageKnown {
		t.Fatalf("a nil resolver must not report package knowledge: %+v", facts)
	}

	hidden := filepath.Join(dir, ".hidden")
	if err := os.WriteFile(hidden, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if facts := Classify(hidden, nil); !facts.Hidden || facts.Executable {
		t.Errorf("hidden facts = %+v", facts)
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	facts = Classify(link, nil)
	if !facts.Link || !facts.Executable || facts.Kind != File {
		t.Fatalf("link facts = %+v", facts)
	}
	if want, _ := filepath.EvalSymlinks(link); facts.Real != want {
		t.Errorf("Real = %q, want %q", facts.Real, want)
	}

	missing := Classify(filepath.Join(dir, "gone"), nil)
	if missing.Kind != Missing || missing.Executable {
		t.Errorf("missing facts = %+v", missing)
	}
}
