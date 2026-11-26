package trust

import (
	"os"
	"testing"
)

func TestUnderAndHidden(t *testing.T) {
	cases := []struct {
		path, root string
		want       bool
	}{
		{"/opt", "/opt", true},
		{"/opt/x", "/opt", true},
		{"/optfoo", "/opt", false},
		{"/etc/profile.d/x.sh", "/etc/profile.d", true},
		{"/etc/profile.dx", "/etc/profile.d", false},
		{"/", "/", true},
		{"/usr", "/", true},
		{"/etc/passwd", "/", true},
	}
	for _, c := range cases {
		if got := Under(c.path, c.root); got != c.want {
			t.Errorf("Under(%q, %q) = %v, want %v", c.path, c.root, got, c.want)
		}
	}
	hidden := []struct {
		path string
		want bool
	}{
		{"/var/lib/vendor/runtime/.attach-loader.sh", true},
		{"/var/lib/vendor/runtime/attach-loader.sh", false},
		{"/.dockerenv", true},
		{"/home/alice/.bashrc", true},
		{"/home/alice/.config/systemd/user/x.service", true},
		{"/home/alice/x", false},
	}
	for _, c := range hidden {
		if got := HiddenPath(c.path); got != c.want {
			t.Errorf("HiddenPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// The lexical facts and the resolved facts describe different things once a
// startup surface links out of its tree: the link lives in /etc/systemd/system,
// the bytes it starts live in /opt.
func TestBuildKeepsLexicalAndResolvedTrees(t *testing.T) {
	facts := Build("/etc/systemd/system/x.service", Attrs{
		Kind: File, Mode: 0o644, UID: 0, Real: "/opt/.x.service", Link: true,
	})
	if !facts.PathStartup || !facts.PathAdmin {
		t.Errorf("lexical facts = %+v", facts)
	}
	if facts.Startup || !facts.AdminLayer {
		t.Errorf("resolved tree facts = %+v", facts)
	}
	if facts.PathHidden || !facts.Hidden {
		t.Errorf("hidden: resolved=%v lexical=%v, want true/false", facts.Hidden, facts.PathHidden)
	}
}

func TestBuildSpecialBits(t *testing.T) {
	facts := Build("/usr/local/bin/helper", Attrs{
		Kind: File, Mode: os.ModeSetuid | 0o755, UID: 0, ParentWritable: true,
	})
	if !facts.Setuid || !facts.Executable || !facts.ParentWritable {
		t.Errorf("special-bit facts = %+v", facts)
	}
}

func TestStartupPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/etc/profile", true},
		{"/etc/profile.d/vendor-runtime-loader.sh", true},
		{"/etc/systemd/system/x.service", true},
		{"/usr/lib/systemd/system/x.service", true},
		{"/root/.bashrc", true},
		{"/home/alice/.profile", true},
		{"/home/alice/.config/fish/config.fish", true},
		{"/home/alice/project/.bashrc", false},
		{"/opt/vendor/tools/vendor-sync-probe", false},
		{"/var/lib/vendor/runtime/.attach-loader.sh", false},
	}
	for _, c := range cases {
		if got := StartupPath(c.path); got != c.want {
			t.Errorf("StartupPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestSkelTemplate(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/etc/skel/.bashrc", true},
		{"/etc/skel/.profile", true},
		{"/etc/skel/.config/fish/config.fish", true},
		{"/etc/skel/README", false},
		{"/etc/skel/.ssh/authorized_keys", false},
		{"/etc/skelx/.bashrc", false},
	}
	for _, c := range cases {
		if got := SkelTemplate(c.path); got != c.want {
			t.Errorf("SkelTemplate(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestClassifyAdminLayer(t *testing.T) {
	facts := Classify("/opt/vendor/tools/vendor-sync-probe", nil)
	if !facts.AdminLayer || facts.TrustedRoot || facts.Kind != Missing {
		t.Errorf("admin-layer path facts = %+v", facts)
	}
	facts = Classify("/usr/bin/curl", nil)
	if !facts.TrustedRoot || facts.AdminLayer {
		t.Errorf("trusted-root path facts = %+v", facts)
	}
}
