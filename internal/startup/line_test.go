package startup

import (
	"testing"

	"karma/internal/trust"
)

// A citation is only useful when it points at the line the parser read. The
// direct parsers and the shell parsers once disagreed about zero- or one-based
// line numbers; these cases pin the answer at the Editor boundary.
func TestPAMEdgeCitesTheModuleLine(t *testing.T) {
	path := "/etc/pam.d/common-auth"
	body := "# header\nauth required /lib/security/pam_unix.so\n"
	facts := func(path string) trust.Facts {
		return trust.Build(path, trust.Attrs{Kind: trust.File, Mode: 0o644, UID: 0, Real: path, CTime: 900})
	}
	edges := Analyze(NewCorpus([]File{{
		Path: path, Surface: SurfacePAM, Dialect: PAMDialect, Body: body,
	}}, nil, facts))
	edge, ok := findEdge(edges, "pam", "/lib/security/pam_unix.so")
	if !ok {
		t.Fatalf("PAM edge missing: %+v", edges)
	}
	if edge.Line != 2 || edge.Source != "auth required /lib/security/pam_unix.so" {
		t.Errorf("PAM citation = line %d %q, want line 2", edge.Line, edge.Source)
	}
}

func TestEvalEdgeCitesTheOuterLine(t *testing.T) {
	body := "#!/bin/sh\n# header\neval 'source /opt/vendor/env.sh'\n"
	edges := shellEdges(body, rawEdge{surface: SurfaceProfile, trigger: "/etc/profile"})
	if len(edges) != 1 || edges[0].line != 3 {
		t.Errorf("eval edges = %+v, want one edge on line 3", edges)
	}
}

func TestFstabEdgeCitesTheMountRow(t *testing.T) {
	path := "/etc/fstab"
	body := "# fstab\nattacker:/export /usr nfs4 ro\n"
	facts := func(path string) trust.Facts {
		return trust.Build(path, trust.Attrs{Kind: trust.File, Mode: 0o644, UID: 0, Real: path, CTime: 900})
	}
	edges := Analyze(NewCorpus([]File{{
		Path: path, Surface: SurfaceSystem, Dialect: SystemDialect, Body: body,
	}}, nil, facts))
	edge, ok := findEdge(edges, "fstab", "/usr")
	if !ok {
		t.Fatalf("fstab row missing: %+v", edges)
	}
	if edge.Line != 2 || edge.Source != "attacker:/export /usr nfs4 ro" {
		t.Errorf("fstab citation = line %d %q, want line 2", edge.Line, edge.Source)
	}
}

func TestCrypttabEdgeCitesTheVolumeRow(t *testing.T) {
	path := "/etc/crypttab"
	body := "# crypttab\ncrypt /dev/vdb none discard\n"
	facts := func(path string) trust.Facts {
		return trust.Build(path, trust.Attrs{Kind: trust.File, Mode: 0o644, UID: 0, Real: path, CTime: 900})
	}
	edges := Analyze(NewCorpus([]File{{
		Path: path, Surface: SurfaceSystem, Dialect: SystemDialect, Body: body,
	}}, nil, facts))
	edge, ok := findEdge(edges, "crypttab", "/dev/mapper/crypt")
	if !ok {
		t.Fatalf("crypttab row missing: %+v", edges)
	}
	if edge.Line != 2 || edge.Source != "crypt /dev/vdb none discard" {
		t.Errorf("crypttab citation = line %d %q, want line 2", edge.Line, edge.Source)
	}
}

func TestNSSEdgeCitesTheSwitchLine(t *testing.T) {
	path := "/etc/nsswitch.conf"
	body := "# switch\npasswd: files\n"
	facts := func(path string) trust.Facts {
		if path == "/lib/libnss_files.so.2" {
			return trust.Build(path, trust.Attrs{Kind: trust.File, Mode: 0o755, UID: 0, Real: path})
		}
		return trust.Build(path, trust.Attrs{Kind: trust.File, Mode: 0o644, UID: 0, Real: path, CTime: 900})
	}
	corpus := NewCorpus([]File{{
		Path: path, Surface: SurfaceSystem, Dialect: SystemDialect, Body: body,
	}}, nil, facts)
	corpus.fs = fakeFS{globs: map[string][]string{
		"/lib/libnss_files.so.2": {"/lib/libnss_files.so.2"},
	}}
	edges := Analyze(corpus)
	edge, ok := findEdge(edges, "nss", "/lib/libnss_files.so.2")
	if !ok {
		t.Fatalf("NSS edge missing: %+v", edges)
	}
	if edge.Line != 2 || edge.Source != "passwd: files" {
		t.Errorf("NSS citation = line %d %q, want line 2", edge.Line, edge.Source)
	}
}
