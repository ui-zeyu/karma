package startup

import (
	"context"
	"io/fs"
	"testing"
	"time"

	"karma/internal/trust"
)

type fakeEntry string

func (e fakeEntry) Name() string               { return string(e) }
func (e fakeEntry) IsDir() bool                { return false }
func (e fakeEntry) Type() fs.FileMode          { return 0 }
func (e fakeEntry) Info() (fs.FileInfo, error) { return nil, fs.ErrNotExist }

type fakeFS struct {
	files map[string]string
	dirs  map[string][]fs.DirEntry
	globs map[string][]string
	links map[string]string
	fail  map[string]error
}

func (f fakeFS) ReadFile(name string) ([]byte, error) {
	if err, ok := f.fail[name]; ok {
		return nil, err
	}
	if body, ok := f.files[name]; ok {
		return []byte(body), nil
	}
	return nil, fs.ErrNotExist
}

func (f fakeFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if entries, ok := f.dirs[name]; ok {
		return entries, nil
	}
	return nil, fs.ErrNotExist
}

func (f fakeFS) Glob(pattern string) ([]string, error) { return f.globs[pattern], nil }

func (f fakeFS) Readlink(name string) (string, error) {
	if target, ok := f.links[name]; ok {
		return target, nil
	}
	return "", fs.ErrNotExist
}

func (f fakeFS) Stat(name string) (fs.FileInfo, error) {
	if err, ok := f.fail[name]; ok {
		return nil, err
	}
	if _, ok := f.files[name]; ok {
		return fakeInfo{}, nil
	}
	return nil, fs.ErrNotExist
}

// fakeInfo is the minimal answer Stat needs: existence, not metadata.
type fakeInfo struct{}

func (fakeInfo) Name() string       { return "" }
func (fakeInfo) Size() int64        { return 0 }
func (fakeInfo) Mode() fs.FileMode  { return 0 }
func (fakeInfo) ModTime() time.Time { return time.Time{} }
func (fakeInfo) IsDir() bool        { return false }
func (fakeInfo) Sys() any           { return nil }

func TestCollectSystemd(t *testing.T) {
	tree := fakeFS{
		files: map[string]string{
			"/etc/systemd/system/preview.service":             "[Service]\nExecStart=/opt/preview/bin\n",
			"/etc/systemd/system/preview.service.d/50-x.conf": "[Service]\nUser=preview\n",
			"/etc/profile.d/vendor-runtime-loader.sh":         "export VENDOR_RUNTIME_LOADER=/var/lib/x/.loader.sh\n",
		},
		dirs: map[string][]fs.DirEntry{
			"/etc/systemd/system": {
				fakeEntry("preview.service"),
				fakeEntry("preview.service.d"),
				fakeEntry("multi-user.target.wants"),
			},
			"/etc/systemd/system/preview.service.d": {
				fakeEntry("50-x.conf"),
			},
			"/etc/systemd/system/multi-user.target.wants": {
				fakeEntry("preview.service"),
			},
		},
		globs: map[string][]string{
			"/etc/systemd/system":           {"/etc/systemd/system"},
			"/run/systemd/system":           nil,
			"/usr/local/lib/systemd/system": nil,
			"/etc/systemd/user":             nil,
			"/root/.config/systemd/user":    nil,
			"/home/*/.config/systemd/user":  nil,
			"/etc/profile":                  nil,
			"/etc/profile.d/*.sh":           {"/etc/profile.d/vendor-runtime-loader.sh"},
			"/etc/bash.bashrc":              nil,
			"/etc/bashrc":                   nil,
			"/etc/zsh/zshenv":               nil,
			"/etc/zsh/zprofile":             nil,
			"/etc/zsh/zshrc":                nil,
			"/etc/zsh/zlogin":               nil,
			"/etc/environment":              nil,
			"/root/.bashrc":                 nil,
			"/root/.bash_profile":           nil,
			"/root/.bash_login":             nil,
			"/root/.profile":                nil,
			"/root/.bash_logout":            nil,
			"/root/.zshrc":                  nil,
			"/root/.zprofile":               nil,
			"/root/.zshenv":                 nil,
			"/root/.zlogin":                 nil,
			"/home/*/.bashrc":               nil,
			"/home/*/.bash_profile":         nil,
			"/home/*/.bash_login":           nil,
			"/home/*/.profile":              nil,
			"/home/*/.bash_logout":          nil,
			"/home/*/.zshrc":                nil,
			"/home/*/.zprofile":             nil,
			"/home/*/.zshenv":               nil,
			"/home/*/.zlogin":               nil,
		},
	}
	corpus := CollectScoped(context.Background(), tree, func(path string) trust.Facts {
		return trust.Build(path, trust.Attrs{Kind: trust.File, Mode: 0o644, UID: 0, Real: path})
	}, AllScope())
	if len(corpus.files) != 3 {
		t.Fatalf("collected %d files, want 3: %+v", len(corpus.files), corpus.files)
	}
	if corpus.enabled["preview.service"] != "/etc/systemd/system/multi-user.target.wants/preview.service" {
		t.Errorf("enabled = %+v", corpus.enabled)
	}
	units := map[string]File{}
	for _, file := range corpus.files {
		units[file.Path] = file
	}
	dropIn := units["/etc/systemd/system/preview.service.d/50-x.conf"]
	if !dropIn.DropIn || dropIn.Unit != "preview.service" || dropIn.Surface != SurfaceSystemd {
		t.Errorf("drop-in = %+v", dropIn)
	}
	profile := units["/etc/profile.d/vendor-runtime-loader.sh"]
	if profile.Surface != SurfaceProfile || profile.Dialect != ShellDialect {
		t.Errorf("profile file = %+v", profile)
	}
}

// The skeleton templates are login files for every account created after the
// change, so the profile surface reads them like any other login file.
func TestCollectSkelTemplate(t *testing.T) {
	tree := fakeFS{
		files: map[string]string{"/etc/skel/.profile": "export LOADER=/opt/vendor/.loader.sh\n"},
		globs: map[string][]string{"/etc/skel/.profile": {"/etc/skel/.profile"}},
	}
	corpus := CollectScoped(context.Background(), tree, func(path string) trust.Facts {
		return trust.Build(path, trust.Attrs{Kind: trust.File, Mode: 0o644, UID: 0, Real: path})
	}, AllScope())
	if len(corpus.files) != 1 {
		t.Fatalf("collected %d files, want 1: %+v", len(corpus.files), corpus.files)
	}
	file := corpus.files[0]
	if file.Path != "/etc/skel/.profile" || file.Surface != SurfaceProfile || file.Dialect != ShellDialect {
		t.Errorf("skel template = %+v", file)
	}
}

// A startup file the collector found but could not read is a coverage gap; the
// corpus names it so the audit can state it as coverage.
func TestCollectUnreadable(t *testing.T) {
	tree := fakeFS{
		files: map[string]string{"/etc/profile": "export X=/opt/x\n"},
		globs: map[string][]string{"/etc/profile": {"/etc/profile"}},
		fail:  map[string]error{"/etc/profile": fs.ErrPermission},
	}
	corpus := CollectScoped(context.Background(), tree, func(path string) trust.Facts { return trust.Facts{Path: path} }, AllScope())
	if len(corpus.files) != 0 {
		t.Fatalf("an unreadable file should not enter the corpus: %+v", corpus.files)
	}
	if got := corpus.Unreadable(); len(got) != 1 || got[0] != "/etc/profile" {
		t.Errorf("unreadable = %v", got)
	}
}

// The native collector and the sh parser classify paths with one function, so
// a path in a collector list cannot land on a different surface depending on
// the source. This table names a representative path for every surface.
func TestFishAndZlogoutAreProfileSurfaces(t *testing.T) {
	tree := fakeFS{files: map[string]string{
		"/etc/fish/config.fish": "set -x APP_HOME /opt/agent\n",
		"/root/.zlogout":        "source /opt/logout.sh\n",
	}}
	corpus := CollectScoped(context.Background(), tree, func(path string) trust.Facts {
		return trust.Facts{Path: path}
	}, Profile)
	if len(corpus.files) != 2 {
		t.Fatalf("profile files = %+v, want fish and zlogout", corpus.files)
	}
	for _, file := range corpus.files {
		if file.Surface != SurfaceProfile || file.Dialect != ShellDialect {
			t.Errorf("%s = %s/%d, want profile/shell", file.Path, file.Surface, file.Dialect)
		}
	}
}

func TestClassifyPathCoversEverySurface(t *testing.T) {
	cases := []struct {
		path    string
		surface Surface
		dialect Dialect
	}{
		{"/etc/systemd/system/x.service", SurfaceSystemd, UnitDialect},
		{"/etc/systemd/system/x.service.d/50.conf", SurfaceSystemd, UnitDialect},
		{"/etc/profile", SurfaceProfile, ShellDialect},
		{"/etc/profile.d/x.sh", SurfaceProfile, ShellDialect},
		{"/etc/environment", SurfaceProfile, EnvDialect},
		{"/etc/bash.bash_logout", SurfaceProfile, ShellDialect},
		{"/etc/skel/.profile", SurfaceProfile, ShellDialect},
		{"/home/alice/.profile", SurfaceProfile, ShellDialect},
		{"/etc/crontab", SurfaceCron, CronDialect},
		{"/etc/cron.daily/x", SurfaceCron, ShellDialect},
		{"/etc/rc.local", SurfaceInit, ShellDialect},
		{"/etc/ld.so.preload", SurfaceLoader, LoaderDialect},
		{"/etc/udev/rules.d/x.rules", SurfaceUdev, UdevDialect},
		{"/etc/ssh/sshd_config", SurfaceSSH, SSHConfigDialect},
		{"/etc/ssh/ssh_config", SurfaceSSH, SSHConfigDialect},
		{"/etc/ssh/ssh_config.d/10-x.conf", SurfaceSSH, SSHConfigDialect},
		{"/root/.ssh/config", SurfaceSSH, SSHConfigDialect},
		{"/etc/ssh/authorized_keys", SurfaceSSH, AuthorizedKeysDialect},
		{"/etc/ssh/sshrc", SurfaceSSH, ShellDialect},
		{"/etc/pam.d/sshd", SurfacePAM, PAMDialect},
		{"/etc/update-motd.d/10-banner", SurfacePAM, ShellDialect},
		{"/etc/systemd/system-generators/x", SurfaceSystemd, GeneratorsDialect},
		{"/usr/lib/systemd/user-generators/x", SurfaceSystemd, GeneratorsDialect},
		{"/etc/supervisor/conf.d/x.conf", SurfaceSupervisor, UnitDialect},
		{"/etc/xinetd.conf", SurfaceSupervisor, XinetdDialect},
		{"/etc/xinetd.d/tftp", SurfaceSupervisor, XinetdDialect},
		{"/etc/s6/services/x/run", SurfaceSupervisor, ShellDialect},
		{"/etc/xdg/autostart/x.desktop", SurfaceXdg, UnitDialect},
		{"/etc/apt/apt.conf.d/01x", SurfaceApt, AptDialect},
		{"/etc/modprobe.d/x.conf", SurfaceModule, ModprobeDialect},
		{"/etc/fstab", SurfaceSystem, SystemDialect},
		{"/etc/crypttab", SurfaceSystem, SystemDialect},
		{"/etc/nsswitch.conf", SurfaceSystem, SystemDialect},
		{"/etc/hosts.allow", SurfaceSystem, SystemDialect},
	}
	for _, c := range cases {
		surface, dialect, ok := classifyPath(c.path)
		if !ok {
			t.Errorf("classifyPath(%q): no surface claims the path", c.path)
		}
		if surface != c.surface || dialect != c.dialect {
			t.Errorf("classifyPath(%q) = %s/%d, want %s/%d",
				c.path, surface, dialect, c.surface, c.dialect)
		}
	}
}

func TestCollectCapsOneFile(t *testing.T) {
	big := make([]byte, maxFileBytes+1)
	tree := fakeFS{
		files: map[string]string{"/etc/profile": string(big)},
		globs: map[string][]string{"/etc/profile": {"/etc/profile"}},
	}
	corpus := CollectScoped(context.Background(), tree, func(path string) trust.Facts { return trust.Facts{Path: path} }, AllScope())
	if len(corpus.files) != 1 {
		t.Fatalf("files = %+v", corpus.files)
	}
	if len(corpus.files[0].Body) != maxFileBytes {
		t.Errorf("body length = %d, want %d", len(corpus.files[0].Body), maxFileBytes)
	}
}

// fakeLink is a directory entry that states it is a symlink; the wants
// directories use it to stand for systemd's enablement links.
type fakeLink string

func (e fakeLink) Name() string               { return string(e) }
func (e fakeLink) IsDir() bool                { return false }
func (e fakeLink) Type() fs.FileMode          { return fs.ModeSymlink }
func (e fakeLink) Info() (fs.FileInfo, error) { return nil, fs.ErrNotExist }

// An enabled vendor unit is an activation edge: the admin wants link names a
// unit whose body lives in the distribution tree. Without reading the target,
// the audit sees the link and knows nothing about what the service runs.
func TestCollectEnabledVendorUnit(t *testing.T) {
	vendor := "/usr/lib/systemd/system/vendor.service"
	tree := fakeFS{
		files: map[string]string{
			vendor: "[Service]\nExecStart=/opt/vendor/agent --sync\n",
		},
		dirs: map[string][]fs.DirEntry{
			"/etc/systemd/system":                         {fakeEntry("multi-user.target.wants")},
			"/etc/systemd/system/multi-user.target.wants": {fakeLink("vendor.service")},
		},
		globs: map[string][]string{
			"/etc/systemd/system": {"/etc/systemd/system"},
		},
		links: map[string]string{
			"/etc/systemd/system/multi-user.target.wants/vendor.service": vendor,
		},
	}
	corpus := CollectScoped(context.Background(), tree, func(path string) trust.Facts {
		return trust.Build(path, trust.Attrs{Kind: trust.File, Mode: 0o755, UID: 0, Real: path})
	}, AllScope())
	found := false
	for _, file := range corpus.files {
		if file.Path == vendor {
			found = true
		}
	}
	if !found {
		t.Fatalf("the enabled vendor unit was not read: %+v", corpus.files)
	}
	edges := Analyze(corpus)
	for _, edge := range edges {
		if edge.Trigger == vendor && edge.Target == "/opt/vendor/agent" {
			if edge.Phase != BootEnabled {
				t.Errorf("phase = %s, want %s", edge.Phase, BootEnabled)
			}
			return
		}
	}
	t.Fatalf("no edge from the vendor unit: %+v", edges)
}

// TestCollectScopedStopsOnCancel pins the interrupt checkpoint: a canceled
// run does not read a single startup file.
func TestCollectScopedStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tree := fakeFS{files: map[string]string{"/etc/ld.so.preload": "/tmp/zz.so\n"}}
	corpus := CollectScoped(ctx, tree, func(path string) trust.Facts { return trust.Facts{Path: path} }, Loader)
	if len(corpus.files) != 0 {
		t.Fatalf("a canceled walk read %d files", len(corpus.files))
	}
}
