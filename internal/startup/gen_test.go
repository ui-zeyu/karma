package startup

import (
	"context"
	"io/fs"
	"testing"
	"time"
)

type genEntry struct{ name string }

func (e genEntry) Name() string      { return e.name }
func (e genEntry) IsDir() bool       { return false }
func (e genEntry) Type() fs.FileMode { return 0 }
func (e genEntry) Info() (fs.FileInfo, error) {
	return genInfo{}, nil
}

type genInfo struct{}

func (genInfo) Name() string       { return "x" }
func (genInfo) Size() int64        { return 1 }
func (genInfo) Mode() fs.FileMode  { return 0o755 }
func (genInfo) ModTime() time.Time { return time.Time{} }
func (genInfo) IsDir() bool        { return false }
func (genInfo) Sys() any           { return nil }

func TestGeneratorEdges(t *testing.T) {
	tree := fakeFS{
		files: map[string]string{
			"/proc/1/comm": "systemd\n",
			"/run/systemd/system-generators/zz-probe": "#!/bin/sh\n",
		},
		dirs: map[string][]fs.DirEntry{
			"/run/systemd/system-generators":     {genEntry{"zz-probe"}},
			"/etc/systemd/system-generators":     {},
			"/usr/lib/systemd/system-generators": {},
		},
	}
	edges := Analyze(CollectScoped(context.Background(), tree, allFiles, Systemd))
	if len(edges) != 1 {
		t.Fatalf("edges = %+v, want one generator self-edge", edges)
	}
	edge := edges[0]
	if edge.Surface != SurfaceSystemd || edge.Phase != BootEnabled ||
		edge.Mechanism != "generator" || edge.Kind != Exec ||
		edge.Trigger != "/run/systemd/system-generators/zz-probe" || edge.Target != edge.Trigger {
		t.Errorf("generator edge = %+v", edge)
	}
	// A host whose init is not systemd never acts on a generator, and the
	// skip is stated in coverage — a silent skip is how vendor enablement
	// once vanished on a healthy host.
	tree.files["/proc/1/comm"] = "supervisord\n"
	corpus := CollectScoped(context.Background(), tree, allFiles, Systemd)
	if edges := Analyze(corpus); len(edges) != 0 {
		t.Errorf("edges under a non-systemd init = %+v", edges)
	}
	gaps := corpus.Gaps()
	if len(gaps) != 1 || !contains(gaps[0], "supervisord") {
		t.Errorf("coverage under a non-systemd init = %v, want the stated skip", gaps)
	}
	// A comm the collector cannot read is a gap too, for its own reason.
	delete(tree.files, "/proc/1/comm")
	corpus = CollectScoped(context.Background(), tree, allFiles, Systemd)
	Analyze(corpus)
	gaps = corpus.Gaps()
	if len(gaps) != 1 || !contains(gaps[0], "init check failed") {
		t.Errorf("coverage without /proc/1/comm = %v, want the failed-check gap", gaps)
	}
}
