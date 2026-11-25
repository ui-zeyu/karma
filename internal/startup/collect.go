package startup

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"karma/internal/localfs"
)

// FS is what the collector reads: the host's filesystem in production, a test
// tree in tests.
type FS interface {
	ReadFile(name string) ([]byte, error)
	ReadDir(name string) ([]fs.DirEntry, error)
	Glob(pattern string) ([]string, error)
	Readlink(name string) (string, error)
}

// OSFS is the native source's filesystem.
type OSFS struct{}

// ReadFile opens non-blocking and reads a regular file only: a FIFO or
// directory planted at a startup path is not a body and cannot hang the
// collection. A missing path and a non-regular one both read as ErrNotExist,
// which the collector skips; a regular file that cannot be opened is the
// unreadable case the note names.
func (OSFS) ReadFile(name string) ([]byte, error) {
	info, err := os.Stat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fs.ErrNotExist
	}
	return localfs.Cat(name)
}
func (OSFS) ReadDir(name string) ([]fs.DirEntry, error) { return os.ReadDir(name) }
func (OSFS) Glob(pattern string) ([]string, error)      { return filepath.Glob(pattern) }
func (OSFS) Readlink(name string) (string, error)       { return os.Readlink(name) }

// maxFileBytes bounds one startup file. Unit files are a few hundred bytes; a
// profile script a few kilobytes. A file past this is cut rather than allowed
// to fill the collection with a log someone wrote at a startup path.
const maxFileBytes = 64 << 10

// unitDirs are the administrator's systemd layers, in no particular order: the
// unit fold states each file's precedence itself.
var unitDirs = []string{
	"/etc/systemd/system",
	"/run/systemd/system",
	"/usr/local/lib/systemd/system",
	"/etc/systemd/user",
	"/root/.config/systemd/user",
	"/home/*/.config/systemd/user",
}

// profileFiles are the login and interactive-shell files. /etc/profile.d is a
// glob because a distribution's profile loops over that directory; the fixed
// files are the shells' own names, and a file that does not exist is simply
// not collected.
var profileFiles = []string{
	"/etc/profile",
	"/etc/profile.d/*.sh",
	"/etc/bash.bashrc",
	"/etc/bashrc",
	"/etc/bash.bash_logout",
	"/etc/zsh/zshenv",
	"/etc/zsh/zprofile",
	"/etc/zsh/zshrc",
	"/etc/zsh/zlogin",
	"/etc/environment",
	"/root/.bashrc",
	"/root/.bash_profile",
	"/root/.bash_login",
	"/root/.profile",
	"/root/.bash_logout",
	"/root/.zshrc",
	"/root/.zprofile",
	"/root/.zshenv",
	"/root/.zlogin",
	"/home/*/.bashrc",
	"/home/*/.bash_profile",
	"/home/*/.bash_login",
	"/home/*/.profile",
	"/home/*/.bash_logout",
	"/home/*/.zshrc",
	"/home/*/.zprofile",
	"/home/*/.zshenv",
	"/home/*/.zlogin",
	// The skeleton templates are copied into every new home. A source or export
	// here becomes a login edge for accounts created after the change.
	"/etc/skel/.bashrc",
	"/etc/skel/.bash_profile",
	"/etc/skel/.bash_login",
	"/etc/skel/.profile",
	"/etc/skel/.bash_logout",
	"/etc/skel/.zshrc",
	"/etc/skel/.zprofile",
	"/etc/skel/.zshenv",
	"/etc/skel/.zlogin",
}

// cronFiles are the scheduled surfaces: the system tables, the cron.d drop-ins,
// the user spool, the run-parts directories and the at spool.
var cronFiles = []string{
	"/etc/crontab",
	"/etc/anacrontab",
	"/etc/cron.d/*",
	"/var/spool/cron/crontabs/*",
	"/var/spool/cron/*",
	"/etc/cron.daily/*",
	"/etc/cron.hourly/*",
	"/etc/cron.weekly/*",
	"/etc/cron.monthly/*",
	"/var/spool/cron/atjobs/*",
	"/var/spool/at/*",
}

// initFiles are the SysV boot scripts and the two classic boot hooks. The
// runlevel directories are read separately: their links are enablement, not
// another copy of the script.
var initFiles = []string{
	"/etc/rc.local",
	"/etc/rc.d/rc.local",
	"/etc/init.sh",
	"/etc/init.d/*",
}

// loaderFiles is the dynamic loader's preload list. ld.so.conf names
// directories rather than files and is a search-path question, not an edge.
var loaderFiles = []string{"/etc/ld.so.preload"}

// udevFiles are the administrator's rule layers; the vendor tree under
// /usr/lib/udev/rules.d is the distribution's baseline and is not read.
var udevFiles = []string{"/etc/udev/rules.d/*.rules", "/run/udev/rules.d/*.rules"}

// sshFiles are the ssh daemon's program hooks, the login rc files, and the
// authorized_keys files. A key's options field is where a forced command
// lives.
var sshFiles = []string{
	"/etc/ssh/sshd_config",
	"/etc/ssh/sshd_config.d/*",
	"/etc/ssh/sshrc",
	"/root/.ssh/rc",
	"/home/*/.ssh/rc",
	"/root/.ssh/authorized_keys",
	"/home/*/.ssh/authorized_keys",
	"/etc/ssh/authorized_keys",
	"/etc/ssh/authorized_keys.d/*",
}

// pamFiles are the PAM service stacks; only pam_exec.so carries a program.
var pamFiles = []string{"/etc/pam.d/*"}

// supervisorFiles are the process supervisors and the container entrypoint:
// supervisor INI sections, s6 run/up scripts, and the docker entrypoint
// directories.
var supervisorFiles = []string{
	"/etc/supervisor/supervisord.conf",
	"/etc/supervisor/conf.d/*.conf",
	"/etc/supervisord.conf",
	"/etc/supervisord.d/*.ini",
	"/etc/s6/services/*/run",
	"/etc/services.d/*/run",
	"/etc/s6-overlay/s6-rc.d/*/run",
	"/etc/s6-overlay/s6-rc.d/*/up",
	"/docker-entrypoint.d/*.sh",
	"/docker-entrypoint-initdb.d/*.sh",
	"/entrypoint.d/*.sh",
}

// xdgFiles are the session autostart entries.
var xdgFiles = []string{
	"/etc/xdg/autostart/*.desktop",
	"/root/.config/autostart/*.desktop",
	"/home/*/.config/autostart/*.desktop",
}

// aptFiles are apt's own configuration and the drop-in directory; the hook
// keys in them name commands apt runs as root.
var aptFiles = []string{"/etc/apt/apt.conf", "/etc/apt/apt.conf.d/*"}

// moduleFiles are the modprobe configuration layers an administrator writes.
var moduleFiles = []string{
	"/etc/modprobe.d/*.conf",
	"/run/modprobe.d/*.conf",
	"/usr/local/lib/modprobe.d/*.conf",
}

// Collect reads the startup surfaces through fsys and hands the files to the
// analysis. Facts are read through the caller's source, so the local host's
// stat and a remote target's stat answer in the same shape.
func Collect(fsys FS, facts FactSource) *Corpus {
	corpus := NewCorpus(nil, nil, facts)
	collectSystemd(fsys, corpus)
	collectSystemdVendorLinks(fsys, corpus)
	collectProfile(fsys, corpus)
	collectCron(fsys, corpus)
	collectInit(fsys, corpus)
	collectLoader(fsys, corpus)
	collectUdev(fsys, corpus)
	collectSSH(fsys, corpus)
	collectPAM(fsys, corpus)
	collectSupervisor(fsys, corpus)
	collectXdg(fsys, corpus)
	collectApt(fsys, corpus)
	collectModule(fsys, corpus)
	// A timer or socket reaches its service through Unit=, and that file may
	// live in the distribution tree the collector has not read yet.
	for _, file := range append([]File(nil), corpus.files...) {
		if !strings.HasSuffix(file.Path, ".timer") && !strings.HasSuffix(file.Path, ".socket") {
			continue
		}
		for _, unit := range unitReferences(file.Body) {
			addUnitFile(fsys, corpus, unit)
		}
	}
	// The collectors state the path and the unit metadata; the surface and
	// dialect come from the same classification the sh parser uses, so the two
	// sources cannot disagree about what a collected file is.
	for index := range corpus.files {
		corpus.files[index].Surface, corpus.files[index].Dialect = classifyPath(corpus.files[index].Path)
	}
	return corpus
}

// unitDirsFixed are the unit layers a named unit is looked up in, admin first:
// an administrator's unit shadows the distribution's, the way systemd resolves
// it.
var unitDirsFixed = []string{
	"/etc/systemd/system",
	"/run/systemd/system",
	"/usr/local/lib/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
	"/etc/systemd/user",
	"/root/.config/systemd/user",
}

// addUnitFile reads a named unit from the first layer that carries it. It is
// used for the units a link, a drop-in or a timer names but the collector did
// not walk; an already-read path is a no-op.
func addUnitFile(fsys FS, corpus *Corpus, unit string) {
	if unit == "" || !hasUnitSuffix(unit) || corpus.masked[unit] {
		return
	}
	for _, dir := range unitDirsFixed {
		path := filepath.Join(dir, unit)
		if _, err := fsys.ReadFile(path); err == nil {
			addBody(fsys, corpus, File{Path: path, Unit: unit})
			return
		}
	}
}

// unitReferences reads Unit= and Also= values from a timer, socket or unit
// file. Only those two keys name another unit file; the rest of the file is
// parsed by the dialect.
func unitReferences(body string) []string {
	var units []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		value, ok := strings.CutPrefix(line, "Unit=")
		if !ok {
			value, ok = strings.CutPrefix(line, "Also=")
		}
		if !ok {
			continue
		}
		for _, name := range strings.Fields(value) {
			name = strings.TrimPrefix(name, "-")
			if hasUnitSuffix(name) {
				units = append(units, name)
			}
		}
	}
	return units
}

func collectSystemd(fsys FS, corpus *Corpus) {
	for _, pattern := range unitDirs {
		dirs, err := fsys.Glob(pattern)
		if err != nil {
			continue
		}
		for _, dir := range dirs {
			entries, err := fsys.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				name := entry.Name()
				path := filepath.Join(dir, name)
				switch {
				case hasUnitSuffix(name):
					// A masked unit is a symlink to /dev/null. It shadows the
					// distribution's unit of the same name, so the vendor file
					// must not be read later as if it were active.
					if entry.Type()&fs.ModeSymlink != 0 {
						if target, err := fsys.Readlink(path); err == nil && filepath.Clean(target) == "/dev/null" {
							corpus.masked[name] = true
							continue
						}
					}
					addBody(fsys, corpus, File{Path: path, Unit: name})
				case strings.HasSuffix(name, ".wants"), strings.HasSuffix(name, ".requires"):
					links, err := fsys.ReadDir(path)
					if err != nil {
						continue
					}
					for _, link := range links {
						linkPath := filepath.Join(path, link.Name())
						if _, seen := corpus.enabled[link.Name()]; !seen {
							corpus.enabled[link.Name()] = linkPath
						}
						// The link usually points into the distribution's unit
						// tree. Reading that file is what makes an enabled vendor
						// service an activation edge; the admin link alone names
						// it without stating what it runs.
						if target, err := fsys.Readlink(linkPath); err == nil {
							if !filepath.IsAbs(target) {
								target = filepath.Join(filepath.Dir(linkPath), target)
							}
							target = filepath.Clean(target)
							if hasUnitSuffix(filepath.Base(target)) {
								name := filepath.Base(target)
								addBody(fsys, corpus, File{Path: target, Unit: name})
								if _, seen := corpus.enabled[name]; !seen {
									corpus.enabled[name] = linkPath
								}
							}
						}
					}
				case strings.HasSuffix(name, ".d"):
					unit := strings.TrimSuffix(name, ".d")
					confs, err := fsys.ReadDir(path)
					if err != nil {
						continue
					}
					for _, conf := range confs {
						if !strings.HasSuffix(conf.Name(), ".conf") {
							continue
						}
						addBody(fsys, corpus, File{
							Path:   filepath.Join(path, conf.Name()),
							Unit:   unit,
							DropIn: true,
						})
					}
					// A drop-in for a distribution unit has no ExecStart of its
					// own; the unit file it overrides does.
					addUnitFile(fsys, corpus, unit)
				}
			}
		}
	}
}

// vendorLinkDirs are the distribution's unit trees. Their *.wants and
// *.requires links are where a vendor unit is enabled at boot; the unit file
// itself is read only when a link names it.
var vendorLinkDirs = []string{"/usr/lib/systemd/system", "/lib/systemd/system"}

func collectSystemdVendorLinks(fsys FS, corpus *Corpus) {
	// The distribution's enablement links describe a boot only when systemd is
	// the running init. A container with supervisord or bash as PID 1 carries
	// the image's links but will never act on them.
	if entries, err := fsys.ReadDir("/run/systemd/system"); err != nil || len(entries) == 0 {
		return
	}
	for _, dir := range vendorLinkDirs {
		entries, err := fsys.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasSuffix(name, ".wants") && !strings.HasSuffix(name, ".requires") {
				continue
			}
			linkDir := filepath.Join(dir, name)
			links, err := fsys.ReadDir(linkDir)
			if err != nil {
				continue
			}
			for _, link := range links {
				linkPath := filepath.Join(linkDir, link.Name())
				target, err := fsys.Readlink(linkPath)
				if err != nil {
					continue
				}
				if !filepath.IsAbs(target) {
					target = filepath.Join(filepath.Dir(linkPath), target)
				}
				target = filepath.Clean(target)
				unit := filepath.Base(target)
				if !hasUnitSuffix(unit) || corpus.masked[unit] {
					continue
				}
				if _, seen := corpus.enabled[unit]; !seen {
					corpus.enabled[unit] = linkPath
				}
				addBody(fsys, corpus, File{Path: target, Unit: unit})
			}
		}
	}
}

func collectProfile(fsys FS, corpus *Corpus) {
	for _, pattern := range profileFiles {
		paths, err := fsys.Glob(pattern)
		if err != nil {
			continue
		}
		for _, path := range paths {
			addBody(fsys, corpus, File{Path: path})
		}
	}
}

func addBody(fsys FS, corpus *Corpus, file File) {
	if corpus.seen[file.Path] {
		return
	}
	data, err := fsys.ReadFile(file.Path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			corpus.unreadable[file.Path] = true
		}
		return
	}
	corpus.seen[file.Path] = true
	if len(data) > maxFileBytes {
		data = data[:maxFileBytes]
	}
	file.Body = string(data)
	corpus.files = append(corpus.files, file)
}

func collectCron(fsys FS, corpus *Corpus) {
	for _, pattern := range cronFiles {
		paths, err := fsys.Glob(pattern)
		if err != nil {
			continue
		}
		for _, path := range paths {
			addBody(fsys, corpus, File{Path: path})
		}
	}
}

func collectInit(fsys FS, corpus *Corpus) {
	for _, pattern := range initFiles {
		paths, err := fsys.Glob(pattern)
		if err != nil {
			continue
		}
		for _, path := range paths {
			addBody(fsys, corpus, File{Path: path})
		}
	}
	// An S-prefixed link in a runlevel directory is how a SysV script is
	// enabled; the link name carries the script's own name after its digits.
	for _, pattern := range []string{"/etc/rc*.d", "/etc/rc.d/rc*.d"} {
		dirs, err := fsys.Glob(pattern)
		if err != nil {
			continue
		}
		for _, dir := range dirs {
			entries, err := fsys.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				name := entry.Name()
				if !strings.HasPrefix(name, "S") {
					continue
				}
				script := strings.TrimLeft(name[1:], "0123456789")
				if script == "" {
					continue
				}
				if _, seen := corpus.enabled[script]; !seen {
					corpus.enabled[script] = filepath.Join(dir, name)
				}
			}
		}
	}
}

func collectLoader(fsys FS, corpus *Corpus) {
	for _, path := range loaderFiles {
		addBody(fsys, corpus, File{Path: path})
	}
}

func collectUdev(fsys FS, corpus *Corpus) {
	for _, pattern := range udevFiles {
		paths, err := fsys.Glob(pattern)
		if err != nil {
			continue
		}
		for _, path := range paths {
			addBody(fsys, corpus, File{Path: path})
		}
	}
}

// isCronShellPath reports whether the cron surface file is a shell script
// rather than a crontab table: the run-parts directories and the at spool.
func isCronShellPath(path string) bool {
	for _, prefix := range []string{
		"/etc/cron.daily/", "/etc/cron.hourly/", "/etc/cron.weekly/", "/etc/cron.monthly/",
		"/var/spool/cron/atjobs/", "/var/spool/at/",
	} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func collectSSH(fsys FS, corpus *Corpus) {
	for _, pattern := range sshFiles {
		paths, err := fsys.Glob(pattern)
		if err != nil {
			continue
		}
		for _, path := range paths {
			addBody(fsys, corpus, File{Path: path})
		}
	}
}

func collectPAM(fsys FS, corpus *Corpus) {
	for _, pattern := range pamFiles {
		paths, err := fsys.Glob(pattern)
		if err != nil {
			continue
		}
		for _, path := range paths {
			addBody(fsys, corpus, File{Path: path})
		}
	}
}

func collectSupervisor(fsys FS, corpus *Corpus) {
	for _, pattern := range supervisorFiles {
		paths, err := fsys.Glob(pattern)
		if err != nil {
			continue
		}
		for _, path := range paths {
			addBody(fsys, corpus, File{Path: path})
		}
	}
}

func collectXdg(fsys FS, corpus *Corpus) {
	for _, pattern := range xdgFiles {
		paths, err := fsys.Glob(pattern)
		if err != nil {
			continue
		}
		for _, path := range paths {
			addBody(fsys, corpus, File{Path: path})
		}
	}
}

func collectApt(fsys FS, corpus *Corpus) {
	for _, pattern := range aptFiles {
		paths, err := fsys.Glob(pattern)
		if err != nil {
			continue
		}
		for _, path := range paths {
			addBody(fsys, corpus, File{Path: path})
		}
	}
}

func collectModule(fsys FS, corpus *Corpus) {
	for _, pattern := range moduleFiles {
		paths, err := fsys.Glob(pattern)
		if err != nil {
			continue
		}
		for _, path := range paths {
			addBody(fsys, corpus, File{Path: path})
		}
	}
}

func sshDialect(path string) Dialect {
	switch {
	case isAuthorizedKeysPath(path):
		return AuthorizedKeysDialect
	case isSSHConfigPath(path):
		return SSHConfigDialect
	}
	return ShellDialect
}

func isSSHConfigPath(path string) bool {
	return path == "/etc/ssh/sshd_config" || strings.HasPrefix(path, "/etc/ssh/sshd_config.d/")
}

func isAuthorizedKeysPath(path string) bool {
	return strings.HasSuffix(path, "/.ssh/authorized_keys") ||
		path == "/etc/ssh/authorized_keys" ||
		strings.HasPrefix(path, "/etc/ssh/authorized_keys.d/")
}

func isSSHPath(path string) bool {
	return isSSHConfigPath(path) || isAuthorizedKeysPath(path) ||
		path == "/etc/ssh/sshrc" || strings.HasSuffix(path, "/.ssh/rc")
}

// hasUnitSuffix is the unit file kinds that carry an ExecStart or name one.
// Mount and target units have no process of their own; they are a later
// surface, not a silently dropped edge here.
func hasUnitSuffix(name string) bool {
	switch filepath.Ext(name) {
	case ".service", ".socket", ".timer", ".path":
		return true
	}
	return false
}
