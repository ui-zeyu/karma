package startup

import (
	"context"
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
	Stat(name string) (fs.FileInfo, error)
}

// OSFS is the native source's filesystem.
type OSFS struct{}

// ReadFile opens non-blocking and reads a regular file only: a FIFO or
// directory planted at a startup path is not a body and cannot hang the
// collection. The read is the localfs one, so a missing path, a non-regular
// one and an unreadable one travel as distinct errors the caller can tier.
func (OSFS) ReadFile(name string) ([]byte, error) {
	return localfs.ReadFile(name, 0)
}
func (OSFS) ReadDir(name string) ([]fs.DirEntry, error) { return os.ReadDir(name) }
func (OSFS) Glob(pattern string) ([]string, error)      { return filepath.Glob(pattern) }
func (OSFS) Readlink(name string) (string, error)       { return os.Readlink(name) }
func (OSFS) Stat(name string) (fs.FileInfo, error)      { return os.Stat(name) }

// maxFileBytes bounds one startup file. Unit files are a few hundred bytes; a
// profile script a few kilobytes. A file past this is cut rather than allowed
// to fill the collection with a log someone wrote at a startup path.
const maxFileBytes = 64 << 10

// unitLayer is one directory a unit file may live in, admin before vendor in
// the order systemd resolves them; a glob layer is the per-home tree of every
// account.
type unitLayer struct {
	dir  string
	glob bool
}

// unitLayers is the one table of unit layers. The collector's walk list, the
// fixed lookup list and the vendor link tree all derive from it, so the
// collector and the named-unit lookup cannot disagree about where a unit
// lives.
var unitLayers = []unitLayer{
	{dir: "/etc/systemd/system"},
	{dir: "/run/systemd/system"},
	{dir: "/usr/local/lib/systemd/system"},
	{dir: "/usr/lib/systemd/system"},
	{dir: "/lib/systemd/system"},
	{dir: "/etc/systemd/user"},
	{dir: "/root/.config/systemd/user"},
	{dir: "/home/*/.config/systemd/user", glob: true},
}

// unitDirs are the layers the collector walks: every admin layer, including
// the per-home globs, but not the vendor baseline.
var unitDirs = func() []string {
	var dirs []string
	for _, layer := range unitLayers {
		if !isVendorUnitDir(layer.dir) {
			dirs = append(dirs, layer.dir)
		}
	}
	return dirs
}()

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
	"/etc/zsh/zlogout",
	"/etc/fish/config.fish",
	"/etc/fish/conf.d/*.fish",
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
	"/root/.zlogout",
	"/root/.config/fish/config.fish",
	"/root/.config/fish/conf.d/*.fish",
	"/home/*/.bashrc",
	"/home/*/.bash_profile",
	"/home/*/.bash_login",
	"/home/*/.profile",
	"/home/*/.bash_logout",
	"/home/*/.zshrc",
	"/home/*/.zprofile",
	"/home/*/.zshenv",
	"/home/*/.zlogin",
	"/home/*/.zlogout",
	"/home/*/.config/fish/config.fish",
	"/home/*/.config/fish/conf.d/*.fish",
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
	"/etc/skel/.zlogout",
	"/etc/skel/.config/fish/config.fish",
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

// loaderFiles is the dynamic loader's preload list and its cached search
// results. ld.so.conf names directories rather than files and is a
// search-path question, not an edge; the cache is regenerated by ldconfig,
// so a cache rewritten outside it is a loader-path decision of its own.
var loaderFiles = []string{"/etc/ld.so.preload", "/etc/ld.so.cache"}

// udevFiles are the administrator's rule layers; the vendor tree under
// /usr/lib/udev/rules.d is the distribution's baseline and is not read.
var udevFiles = []string{"/etc/udev/rules.d/*.rules", "/run/udev/rules.d/*.rules"}

// sshFiles are the ssh daemon's program hooks, the client configuration and
// its command hooks, the login rc files, and the authorized_keys files. A
// key's options field is where a forced command lives.
var sshFiles = []string{
	"/etc/ssh/sshd_config",
	"/etc/ssh/sshd_config.d/*",
	"/etc/ssh/ssh_config",
	"/etc/ssh/ssh_config.d/*",
	"/root/.ssh/config",
	"/home/*/.ssh/config",
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

// supervisorFiles are the process supervisors, the internet superservers and
// the container entrypoint: supervisor INI sections, xinetd definitions, s6
// run/up scripts, and the docker entrypoint directories.
var supervisorFiles = []string{
	"/etc/supervisor/supervisord.conf",
	"/etc/supervisor/conf.d/*.conf",
	"/etc/supervisord.conf",
	"/etc/supervisord.d/*.ini",
	"/etc/xinetd.conf",
	"/etc/xinetd.d/*",
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

// Scope selects the startup surfaces one run reads. The bits follow the
// collector table below, so a surface has one name, one bit and one collector.
// A run that asked for services does not pay for cron, udev or the login
// files, and a run that asked for a path can still read every surface when the
// path may be any of them.
type Scope uint16

const (
	Systemd Scope = 1 << iota
	Profile
	Cron
	Init
	Loader
	Udev
	SSH
	PAM
	Supervisor
	XDG
	Apt
	Module
	System
)

// AllScope reads every startup surface.
func AllScope() Scope {
	var scope Scope
	for _, surface := range surfaceRuns {
		scope |= surface.bit
	}
	return scope
}

// Has reports whether the scope selects one surface.
func (s Scope) Has(surface Surface) bool { return s&surfaceBits[surface] != 0 }

// GroupWords lists the surface names one scope group carries, in collector
// order. The table is the only place a surface's groups are named.
func GroupWords(group string) []string {
	var words []string
	for _, surface := range surfaceRuns {
		for _, name := range surface.groups {
			if name == group {
				words = append(words, surface.name)
				break
			}
		}
	}
	return words
}

// SurfaceWords lists the startup surface names in collector order. The CLI's
// scope vocabulary reads this table, so a new surface needs no second list.
func SurfaceWords() []string {
	words := make([]string, 0, len(surfaceRuns))
	for _, surface := range surfaceRuns {
		words = append(words, surface.name)
	}
	return words
}

// ScopeForWords answers the bits of a set of surface names. An unknown name
// contributes nothing; the caller validates the vocabulary.
func ScopeForWords(words []string) Scope {
	var scope Scope
	for _, surface := range surfaceRuns {
		for _, word := range words {
			if surface.name == word {
				scope |= surface.bit
				break
			}
		}
	}
	return scope
}

// SurfaceScope answers the bit of one surface.
func SurfaceScope(surface Surface) Scope { return surfaceBits[surface] }

// surfaceBits is the one mapping from the edge vocabulary to the collector
// bits. The table order defines both.
var surfaceBits = func() map[Surface]Scope {
	bits := make(map[Surface]Scope, len(surfaceRuns))
	for _, surface := range surfaceRuns {
		bits[Surface(surface.name)] = surface.bit
	}
	return bits
}()

// surfaceRun is one surface's collector: the file lists it reads, the link
// walking only systemd needs, and the post pass systemd runs after its own
// collection. The table is the one place a surface is described; Scope,
// CollectScoped and the parsers all derive from it.
type surfaceRun struct {
	name string
	bit  Scope
	// groups are the scope groups the surface belongs to (boot, login,
	// schedule, service, device); the CLI's group vocabulary reads them, so
	// a surface cannot join a group in one package and leave it in another.
	groups   []string
	patterns []string
	run      func(FS, *Corpus)
	// post runs after the surface's own collection, still inside its scope.
	post func(FS, *Corpus)
	// match is the surface's classifier when its vocabulary is semantics
	// rather than globs; every other surface matches through its compiled
	// patterns, so the collector and the classifier share one vocabulary.
	match   func(string) bool
	dialect func(string) Dialect
	parse   func(File, *Corpus) []rawEdge
	// compiled holds the compiled patterns; init fills it for the surfaces
	// without a custom match.
	compiled []func(string) bool
}

// matches answers whether the surface claims a path.
func (s *surfaceRun) matches(path string) bool {
	if s.match != nil {
		return s.match(path)
	}
	for _, match := range s.compiled {
		if match(path) {
			return true
		}
	}
	return false
}

// The compiled matchers derive from the same pattern lists the collectors
// glob, so a collected file classifies as what collected it.
func init() {
	for i := range surfaceRuns {
		surface := &surfaceRuns[i]
		if surface.match != nil {
			continue
		}
		for _, pattern := range surface.patterns {
			surface.compiled = append(surface.compiled, compilePattern(pattern))
		}
	}
}

var surfaceRuns = []surfaceRun{
	{name: "systemd", bit: Systemd, groups: []string{"boot", "service"},
		match: isSystemdUnitPath,
		run: func(fsys FS, corpus *Corpus) {
			collectSystemd(fsys, corpus)
			collectGenerators(fsys, corpus, generatorDirs)
			collectGenerators(fsys, corpus, userGeneratorDirs)
			collectSystemdVendorLinks(fsys, corpus)
		},
		post:    expandUnitTargets,
		dialect: systemdDialect,
		parse:   parseSystemdFile,
	},
	{name: "profile", bit: Profile, groups: []string{"login"}, patterns: profileFiles,
		match: isProfilePath, dialect: profileDialect, parse: parseProfile},
	{name: "cron", bit: Cron, groups: []string{"schedule"}, patterns: cronFiles,
		dialect: cronDialect, parse: parseCron},
	{name: "init", bit: Init, groups: []string{"boot"}, patterns: initFiles, run: collectInit,
		dialect: func(string) Dialect { return ShellDialect }, parse: parseInit},
	{name: "loader", bit: Loader, groups: []string{"boot"}, patterns: loaderFiles,
		dialect: func(string) Dialect { return LoaderDialect }, parse: parseLoader},
	{name: "udev", bit: Udev, groups: []string{"boot", "device"}, patterns: udevFiles,
		dialect: func(string) Dialect { return UdevDialect }, parse: parseUdev},
	{name: "ssh", bit: SSH, groups: []string{"login"}, patterns: sshFiles,
		match: isSSHPath, dialect: sshDialect, parse: parseSSH},
	{name: "pam", bit: PAM, groups: []string{"login"}, patterns: pamFiles, run: collectPAM,
		match: isPAMPath, dialect: pamDialect, parse: parsePAM},
	{name: "supervisor", bit: Supervisor, groups: []string{"service"}, patterns: supervisorFiles,
		dialect: supervisorDialect, parse: parseSupervisor},
	{name: "xdg", bit: XDG, groups: []string{"login"}, patterns: xdgFiles,
		dialect: func(string) Dialect { return UnitDialect }, parse: parseXdg},
	{name: "apt", bit: Apt, groups: []string{"boot"}, patterns: aptFiles,
		dialect: func(string) Dialect { return AptDialect }, parse: parseApt},
	{name: "module", bit: Module, groups: []string{"boot"}, patterns: moduleFiles,
		dialect: func(string) Dialect { return ModprobeDialect }, parse: parseModule},
	{name: "system", bit: System, groups: []string{"boot"}, patterns: systemFiles,
		dialect: func(string) Dialect { return SystemDialect }, parse: parseSystem},
}

// CollectScoped reads the selected startup surfaces. Facts are read through
// the caller's source, so the local host's stat and a remote target's stat
// answer in the same shape. The context stops the walk between surfaces and
// before every file read, so an interrupted run does not wait out the tree.
func CollectScoped(ctx context.Context, fsys FS, facts FactSource, scope Scope) *Corpus {
	corpus := NewCorpus(ctx, fsys, nil, nil, facts)
	for _, surface := range surfaceRuns {
		if scope&surface.bit == 0 {
			continue
		}
		if corpus.stopped() {
			break
		}
		if surface.run != nil {
			surface.run(fsys, corpus)
		} else {
			collectPatterns(fsys, corpus, surface.patterns)
		}
		if surface.post != nil {
			surface.post(fsys, corpus)
		}
	}
	// The collectors state the path and the unit metadata; the surface and
	// dialect come from the same classification the sh parser uses, so the two
	// sources cannot disagree about what a collected file is.
	for index := range corpus.files {
		file := &corpus.files[index]
		surface, dialect, ok := classifyPath(file.Path)
		if !ok {
			// A collected file no surface claims is a collector/classifier
			// drift; the gap states it and the file keeps the systemd
			// reading so the parse dispatch is unchanged.
			corpus.addGap("unclassified startup path: " + file.Path)
		}
		file.Surface, file.Dialect = surface, dialect
	}
	return corpus
}

// expandUnitTargets reads the unit files a timer, socket, path or target
// names. A timer or socket reaches its service through Unit=, Service= or
// Also=, and that file may live in a tree the collector has not read yet.
func expandUnitTargets(fsys FS, corpus *Corpus) {
	for _, file := range append([]File(nil), corpus.files...) {
		if !strings.HasSuffix(file.Path, ".timer") && !strings.HasSuffix(file.Path, ".socket") &&
			!strings.HasSuffix(file.Path, ".path") && !strings.HasSuffix(file.Path, ".target") {
			continue
		}
		for _, unit := range unitReferences(file.Body) {
			addUnitFile(fsys, corpus, unit)
		}
	}
}

// unitDirsFixed are the unit layers a named unit is looked up in, admin first.
var unitDirsFixed = func() []string {
	var dirs []string
	for _, layer := range unitLayers {
		if !layer.glob {
			dirs = append(dirs, layer.dir)
		}
	}
	return dirs
}()

// vendorLinkDirs are the distribution's unit trees. Their *.wants and
// *.requires links are where a vendor unit is enabled at boot; the unit file
// itself is read only when a link names it. They are the vendor layers of
// unitLayers.
var vendorLinkDirs = []string{"/usr/lib/systemd/system", "/lib/systemd/system"}

func isVendorUnitDir(dir string) bool {
	for _, vendor := range vendorLinkDirs {
		if dir == vendor {
			return true
		}
	}
	return false
}

// UnitDirs names the layers a unit file may live in, administrator first. A
// glob entry is a per-user home layer; callers that walk a single unit resolve
// it through LookupUnitFile.
func UnitDirs() []string {
	return append([]string(nil), unitDirsFixed...)
}

// LookupUnitFile resolves a unit name through the same layers the collector
// reads, so the object graph cannot disagree with the activation inventory.
func LookupUnitFile(name string) string {
	return lookupUnitFileFS(OSFS{}, name)
}

func lookupUnitFileFS(fsys FS, name string) string {
	if !IsUnitName(name) {
		return ""
	}
	return resolveUnit(fsys, name)
}

// resolveUnit resolves one unit name through the unit layers, admin first: an
// administrator's unit shadows the distribution's, the way systemd resolves
// it. It is the one lookup the collector and the graph share.
func resolveUnit(fsys FS, name string) string {
	for _, layer := range unitLayers {
		dirs := []string{layer.dir}
		if layer.glob {
			matches, err := fsys.Glob(layer.dir)
			if err != nil {
				continue
			}
			dirs = matches
		}
		for _, dir := range dirs {
			path := filepath.Join(dir, name)
			if _, err := fsys.Stat(path); err == nil {
				return path
			}
		}
	}
	return ""
}

// addUnitFile reads a named unit from the first layer that carries it. It is
// used for the units a link, a drop-in or a timer names but the collector did
// not walk; an already-read path is a no-op.
func addUnitFile(fsys FS, corpus *Corpus, unit string) {
	if unit == "" || !IsUnitName(unit) || corpus.masked[unit] {
		return
	}
	if path := resolveUnit(fsys, unit); path != "" {
		addBody(fsys, corpus, File{Path: path, Unit: unit})
	}
}

// unitReferenceKeys are the unit keys that name another unit file a boot or
// a trigger pulls in.
var unitReferenceKeys = map[string]bool{
	"Unit": true, "Service": true, "Also": true,
	"Requires": true, "Wants": true, "OnFailure": true,
}

// unitReferences reads the keys that name another unit file, from one parse
// of the body — continuation lines included, as the dialect's parser reads
// them.
func unitReferences(body string) []string {
	var units []string
	for _, directive := range parseUnit(body) {
		if !unitReferenceKeys[directive.key] {
			continue
		}
		for _, name := range strings.Fields(directive.value) {
			name = strings.TrimPrefix(name, "-")
			if IsUnitName(name) {
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
				if corpus.stopped() {
					return
				}
				name := entry.Name()
				path := filepath.Join(dir, name)
				switch {
				case IsUnitName(name):
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
			// The layer's own enablement links are the walk it shares with
			// the vendor tree; they come after the entries loop so a mask
			// declared in this layer is known before its links are followed.
			walkUnitLinks(fsys, corpus, dir, false)
		}
	}
}

// walkUnitLinks reads one unit tree's enablement links. The admin's .wants
// and .requires and the vendor tree's are one walk; the vendor tree's links
// describe a boot only when systemd is the running init, and a masked unit is
// neither read nor called enabled on either side.
func walkUnitLinks(fsys FS, corpus *Corpus, dir string, vendor bool) {
	// The distribution's enablement links describe a boot only when systemd is
	// the running init. A container with supervisord or bash as PID 1 carries
	// the image's links but will never act on them — the gate says so, either
	// as a coverage gap for an unreadable comm or as a stated skip.
	if vendor && !systemdIsInit(fsys, corpus) {
		return
	}
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		return
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
			if corpus.masked[link.Name()] {
				continue
			}
			if _, seen := corpus.enabled[link.Name()]; !seen {
				corpus.enabled[link.Name()] = linkPath
			}
			// The link usually points into the distribution's unit
			// tree. Reading that file is what makes an enabled vendor
			// service an activation edge; the link alone names it
			// without stating what it runs.
			target, err := fsys.Readlink(linkPath)
			if err != nil {
				continue
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(linkPath), target)
			}
			target = filepath.Clean(target)
			unit := filepath.Base(target)
			if !IsUnitName(unit) || corpus.masked[unit] {
				continue
			}
			if _, seen := corpus.enabled[unit]; !seen {
				corpus.enabled[unit] = linkPath
			}
			addBody(fsys, corpus, File{Path: target, Unit: unit})
		}
	}
}

func collectSystemdVendorLinks(fsys FS, corpus *Corpus) {
	for _, dir := range vendorLinkDirs {
		walkUnitLinks(fsys, corpus, dir, true)
	}
}

// collectPatterns is the one glob loop every data-listed surface uses. A
// surface with link walking or a permission filter supplies its own run.
func collectPatterns(fsys FS, corpus *Corpus, patterns []string) {
	for _, pattern := range patterns {
		paths, err := fsys.Glob(pattern)
		if err == nil && len(paths) > 0 {
			for _, path := range paths {
				addBody(fsys, corpus, File{Path: path})
			}
			continue
		}
		if !strings.ContainsAny(pattern, "*?[") {
			addBody(fsys, corpus, File{Path: pattern})
		}
	}
}

func addBody(fsys FS, corpus *Corpus, file File) {
	if corpus.stopped() || corpus.seen[file.Path] {
		return
	}
	data, err := fsys.ReadFile(file.Path)
	if err != nil {
		switch {
		case errors.Is(err, fs.ErrNotExist):
			// A fixed path that does not exist is the ordinary case; every
			// surface reads paths most hosts never carry.
		case errors.Is(err, localfs.ErrNotRegular):
			corpus.addGap("startup path holds a non-regular file: " + file.Path)
		default:
			corpus.unreadable[file.Path] = true
		}
		return
	}
	corpus.seen[file.Path] = true
	if len(data) > maxFileBytes {
		data = data[:maxFileBytes]
		corpus.addGap("startup file truncated at 64KiB: " + file.Path)
	}
	file.Body = string(data)
	corpus.files = append(corpus.files, file)
}

func collectInit(fsys FS, corpus *Corpus) {
	collectPatterns(fsys, corpus, initFiles)
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

// isCronShellPath reports whether the cron surface file is a shell script
// rather than a crontab table: the run-parts directories and the at spool.
var cronShellPrefixes = []string{
	"/etc/cron.daily/", "/etc/cron.hourly/", "/etc/cron.weekly/", "/etc/cron.monthly/",
	"/var/spool/cron/atjobs/", "/var/spool/at/",
}

func isCronShellPath(path string) bool {
	for _, prefix := range cronShellPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
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
	collectMotd(fsys, corpus)
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
	switch {
	case path == "/etc/ssh/sshd_config" || strings.HasPrefix(path, "/etc/ssh/sshd_config.d/"):
		return true
	case path == "/etc/ssh/ssh_config" || strings.HasPrefix(path, "/etc/ssh/ssh_config.d/"):
		return true
	case path == "/root/.ssh/config" || strings.HasPrefix(path, "/home/") && strings.HasSuffix(path, "/.ssh/config"):
		return true
	}
	return false
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

// IsUnitName is the unit file kinds the collector reads: the ones with an
// ExecStart, the ones that name one, and the ones that assemble or stage the
// tree itself (mount, swap, target — a target's Requires/Wants chain is how a
// boot pulls other units in). The CLI scope grammar and the object graph use
// the same predicate, so a unit word cannot mean different things per command.
func IsUnitName(name string) bool {
	switch filepath.Ext(name) {
	case ".service", ".socket", ".timer", ".path", ".mount", ".swap", ".target":
		return true
	}
	return false
}
