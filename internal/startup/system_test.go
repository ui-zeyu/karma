package startup

import (
	"context"
	"io/fs"
	"testing"

	"karma/internal/trust"
)

// systemTree builds a corpus over the system's own loaders: the PAM stacks,
// the name-service switch, the wrappers tables, the mount tables, the
// superserver definitions and the login banner.
func systemTree(t *testing.T) []Edge {
	t.Helper()
	tree := fakeFS{
		files: map[string]string{
			"/etc/pam.d/common-auth":   "auth required pam_exec.so /opt/otp/bin\nauth required pam_unix.so\n",
			"/etc/nsswitch.conf":       "passwd: files systemd\n",
			"/etc/hosts.allow":         "sshd : ALL : spawn /bin/echo blocked\n",
			"/etc/hosts.deny":          "ALL : ALL\n",
			"/etc/fstab":               "/dev/vda1 / ext4 defaults 0 1\n",
			"/etc/crypttab":            "data /dev/vdb none\n",
			"/etc/xinetd.conf":         "service t {\n  server = /usr/bin/true\n}\n",
			"/etc/update-motd.d/99-zz": "#!/bin/sh\n/bin/uptime\n",
		},
		globs: map[string][]string{
			"/etc/pam.d/*":        {"/etc/pam.d/common-auth"},
			"/etc/xinetd.conf":    {"/etc/xinetd.conf"},
			"/etc/xinetd.d/*":     nil,
			"/etc/update-motd.d/": nil,
			// The loader search: pam_unix resolves through /usr/lib/security,
			// the NSS module through the multiarch directory.
			"/lib/security/pam_unix.so":               nil,
			"/usr/lib/security/pam_unix.so":           {"/usr/lib/security/pam_unix.so"},
			"/lib/security/libnss_systemd.so.2":       nil,
			"/usr/lib/security/libnss_systemd.so.2":   nil,
			"/lib/*/security/libnss_systemd.so.2":     nil,
			"/usr/lib/*/security/libnss_systemd.so.2": nil,
			"/lib64/security/libnss_systemd.so.2":     nil,
			"/usr/lib64/security/libnss_systemd.so.2": nil,
			"/lib/libnss_systemd.so.2":                nil,
			"/usr/lib/libnss_systemd.so.2":            nil,
			"/lib64/libnss_systemd.so.2":              nil,
			"/usr/lib64/libnss_systemd.so.2":          nil,
			"/lib/*/libnss_systemd.so.2":              {"/lib/x86_64-linux-gnu/libnss_systemd.so.2"},
			"/usr/lib/*/libnss_systemd.so.2":          nil,
		},
		dirs: map[string][]fs.DirEntry{
			"/etc/update-motd.d": {fakeEntry("99-zz")},
		},
	}
	edges := Analyze(CollectScoped(context.Background(), tree, allFiles, AllScope()))
	if len(edges) == 0 {
		t.Fatal("no edges from the system surfaces")
	}
	return edges
}

// allFiles answers every path a regular file, the shape a loader tree has.
func allFiles(path string) trust.Facts {
	return trust.Build(path, trust.Attrs{Kind: trust.File, Real: path})
}

func findEdge(edges []Edge, mechanism Mechanism, target string) (Edge, bool) {
	for _, edge := range edges {
		if edge.Mechanism == mechanism && edge.Target == target {
			return edge, true
		}
	}
	return Edge{}, false
}

func TestSystemSurfacesProduceEdges(t *testing.T) {
	edges := systemTree(t)

	exec, ok := findEdge(edges, "pam_exec", "/opt/otp/bin")
	if !ok {
		t.Fatalf("pam_exec edge missing from %d edges", len(edges))
	}
	if exec.Surface != SurfacePAM || exec.Subject.Class != AccountRoot || exec.Phase != Login {
		t.Errorf("pam_exec edge = %+v", exec)
	}
	module, ok := findEdge(edges, "pam", "/usr/lib/security/pam_unix.so")
	if !ok || module.Kind != Library {
		t.Errorf("pam module edge = %+v (found %t)", module, ok)
	}
	nss, ok := findEdge(edges, "nss", "/lib/x86_64-linux-gnu/libnss_systemd.so.2")
	if !ok || nss.Kind != Library || nss.Trigger != "/etc/nsswitch.conf" {
		t.Errorf("nss edge = %+v (found %t)", nss, ok)
	}
	spawn, ok := findEdge(edges, "spawn", "/bin/echo")
	if !ok || spawn.Kind != Exec || spawn.Surface != SurfaceSystem {
		t.Errorf("spawn edge = %+v (found %t)", spawn, ok)
	}
	server, ok := findEdge(edges, "server", "/usr/bin/true")
	if !ok || server.Surface != SurfaceSupervisor || server.Kind != Exec {
		t.Errorf("xinetd server edge = %+v (found %t)", server, ok)
	}
	fstab, ok := findEdge(edges, "fstab", "/etc/fstab")
	if !ok || fstab.Kind != Config || fstab.Trigger != fstab.Target {
		t.Errorf("fstab self-edge = %+v (found %t)", fstab, ok)
	}
	motd, ok := findEdge(edges, "update-motd", "/etc/update-motd.d/99-zz")
	if !ok || motd.Kind != Exec {
		t.Errorf("motd self-edge = %+v (found %t)", motd, ok)
	}
	if _, ok := findEdge(edges, "exec", "/bin/uptime"); !ok {
		t.Errorf("motd script command edge missing")
	}
}

func TestXinetdServerAcceptsQuotes(t *testing.T) {
	plain := xinetdEdges(File{
		Path: "/etc/xinetd.d/rsync", Surface: SurfaceSupervisor,
		Body: "service rsync\n{\n  server = /usr/bin/rsync\n}\n",
	})
	if len(plain) != 1 || plain[0].target != "/usr/bin/rsync" || plain[0].dynamic {
		t.Errorf("xinetd edges = %+v, want one exec to /usr/bin/rsync", plain)
	}
	quoted := xinetdEdges(File{
		Path: "/etc/xinetd.d/app", Surface: SurfaceSupervisor,
		Body: "service app\n{\n  server = \"/opt/my app/srv\"\n}\n",
	})
	if len(quoted) != 1 || quoted[0].target != "/opt/my app/srv" || quoted[0].dynamic {
		t.Errorf("quoted xinetd edges = %+v, want the unquoted absolute path", quoted)
	}
}

func TestFindLibraryPrefersTheNativeArch(t *testing.T) {
	native := nativeLibDirs()
	if len(native) == 0 {
		t.Skip("no multiarch directories on this architecture")
	}
	want := native[0] + "pam_x.so"
	corpus := NewCorpus(nil, nil, allFiles)
	corpus.fs = fakeFS{globs: map[string][]string{
		want:                           {want},
		"/usr/lib/*/security/pam_x.so": {"/usr/lib/i386-linux-gnu/security/pam_x.so", want},
	}}
	if got := findLibrary("pam_x.so", corpus); got != want {
		t.Errorf("findLibrary = %q, want the native arch copy %q", got, want)
	}
}

func TestMissingPAMModuleBecomesCoverage(t *testing.T) {
	tree := fakeFS{
		files: map[string]string{
			"/etc/pam.d/common-auth": "auth required pam_forensics.so\n",
		},
		globs: map[string][]string{
			"/etc/pam.d/*": {"/etc/pam.d/common-auth"},
		},
	}
	corpus := CollectScoped(context.Background(), tree, allFiles, PAM)
	Analyze(corpus)
	gaps := corpus.Gaps()
	if len(gaps) != 1 || !contains(gaps[0], "pam_forensics.so") {
		t.Errorf("coverage gaps = %v", gaps)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) > 0 && indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for at := 0; at+len(needle) <= len(haystack); at++ {
		if haystack[at:at+len(needle)] == needle {
			return at
		}
	}
	return -1
}

func TestSSHClientConfigCommands(t *testing.T) {
	tree := fakeFS{
		files: map[string]string{
			"/etc/ssh/ssh_config":  "Host *\n  ProxyCommand /usr/bin/nc %h %p\n",
			"/root/.ssh/config":    "Host prod\n  LocalCommand /root/bin/snap\n",
			"/etc/ssh/sshd_config": "AuthorizedKeysCommand /usr/bin/otp-keys\n",
		},
		globs: map[string][]string{
			"/etc/ssh/ssh_config":      {"/etc/ssh/ssh_config"},
			"/root/.ssh/config":        {"/root/.ssh/config"},
			"/etc/ssh/sshd_config":     {"/etc/ssh/sshd_config"},
			"/etc/ssh/sshd_config.d/*": nil,
			"/etc/ssh/ssh_config.d/*":  nil,
		},
	}
	edges := Analyze(CollectScoped(context.Background(), tree, allFiles, SSH))
	proxy, ok := findEdge(edges, "ProxyCommand", "/usr/bin/nc")
	if !ok || proxy.Phase != Session || proxy.Subject.Class != AccountLogin {
		t.Errorf("proxycommand edge = %+v (found %t)", proxy, ok)
	}
	local, ok := findEdge(edges, "LocalCommand", "/root/bin/snap")
	if !ok || local.Subject.Class != AccountRoot {
		t.Errorf("localcommand edge = %+v (found %t)", local, ok)
	}
	keys, ok := findEdge(edges, "AuthorizedKeysCommand", "/usr/bin/otp-keys")
	if !ok || keys.Subject.Class != AccountRoot || keys.Phase != Login {
		t.Errorf("authorizedkeyscommand edge = %+v (found %t)", keys, ok)
	}
}

func TestMountTableRowEdges(t *testing.T) {
	edges := fstabEdges(File{
		Path: "/etc/fstab", Surface: SurfaceSystem,
		Body: "/dev/vda1 / ext4 defaults 0 1\nhost:/export /usr nfs4 ro\n/dev/vdc none swap sw\n# a comment\n",
	})
	if len(edges) != 2 {
		t.Fatalf("fstab edges = %+v, want the root and /usr rows (a swap row names no code path)", edges)
	}
	if edges[0].target != "/" || edges[0].note != "ext4 defaults 0 1" {
		t.Errorf("root row = %+v", edges[0])
	}
	if edges[1].target != "/usr" || edges[1].note != "nfs4 ro" || edges[1].line != 2 {
		t.Errorf("/usr row = %+v", edges[1])
	}
}

func TestCrypttabRowEdges(t *testing.T) {
	edges := crypttabEdges(File{
		Path: "/etc/crypttab", Surface: SurfaceSystem,
		Body: "data /dev/vdb none discard\n",
	})
	if len(edges) != 1 || edges[0].target != "/dev/mapper/data" || edges[0].note != "/dev/vdb none discard" {
		t.Errorf("crypttab edges = %+v", edges)
	}
}

func TestMountUnitStatesWhat(t *testing.T) {
	tree := fakeFS{
		files: map[string]string{
			"/etc/systemd/system/data.mount":  "[Mount]\nWhat=/dev/vdb\nWhere=/data\nType=ext4\nOptions=rw\n",
			"/etc/systemd/system/netfs.mount": "[Mount]\nWhat=nfs-host:/export\nWhere=/mnt/net\nType=nfs4\n",
		},
		dirs: map[string][]fs.DirEntry{
			"/etc/systemd/system": {fakeEntry("data.mount"), fakeEntry("netfs.mount")},
		},
		globs: map[string][]string{
			"/etc/systemd/system":           {"/etc/systemd/system"},
			"/run/systemd/system":           nil,
			"/usr/local/lib/systemd/system": nil,
		},
	}
	edges := Analyze(CollectScoped(context.Background(), tree, allFiles, Systemd))
	var local, net *Edge
	for index := range edges {
		switch edges[index].Target {
		case "/dev/vdb":
			local = &edges[index]
		case "nfs-host:/export":
			net = &edges[index]
		}
	}
	if local == nil || local.Mechanism != "What" || local.Dynamic || !contains(string(local.Note), "type=ext4") {
		t.Errorf("device What edge = %+v, want an absolute edge with the row note", local)
	}
	if net == nil || !net.Dynamic {
		t.Errorf("network What edge = %+v, want dynamic", net)
	}
}

func TestUnitReferencesFollowTheChainKeys(t *testing.T) {
	units := unitReferences("[Unit]\nRequires=data.mount\nWants=net.service other.service\nOnFailure=alert.service\n")
	if len(units) != 4 {
		t.Errorf("unitReferences = %v, want the Requires, Wants and OnFailure chain", units)
	}
}

func TestLoaderCacheIsASelfEdge(t *testing.T) {
	tree := fakeFS{
		files: map[string]string{
			"/etc/ld.so.cache":   "\x00binary-ish bytes\x00",
			"/etc/ld.so.preload": "",
		},
	}
	edges := Analyze(CollectScoped(context.Background(), tree, allFiles, Loader))
	if len(edges) != 1 || edges[0].Mechanism != "ld.so.cache" ||
		edges[0].Trigger != "/etc/ld.so.cache" || edges[0].Target != edges[0].Trigger {
		t.Errorf("loader edges = %+v, want one cache self-edge and no binary line parse", edges)
	}
}
