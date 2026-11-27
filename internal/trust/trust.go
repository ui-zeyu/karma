package trust

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Kind is what a path resolves to.
type Kind uint8

const (
	Missing Kind = iota
	File
	Dir
	Other
)

// Attrs is one path's raw filesystem attributes, before provenance is read
// into them. The collector fills it from the host's own stat.
type Attrs struct {
	Kind Kind
	Mode fs.FileMode // the resolved file's permission and special bits
	UID  int
	GID  int
	// Link is the path itself being a symlink; Real is what it resolves to.
	Link bool
	Real string
	// ParentWritable is whether a directory on the resolved path's chain can
	// be replaced by someone other than root: group/other write, or a non-root
	// owner with the owner bit. ParentOpen is the narrower fact — group/other
	// write alone — and is what a user-owned surface must be judged by.
	ParentWritable bool
	ParentOpen     bool
	Package        string
	PackageKnown   bool
	// Diverted is dpkg's own record that this path is a local diversion: the
	// file is the administrator's declared replacement, and a known-empty
	// ownership answer for it reads as declared, not as a dropped binary.
	Diverted bool
	// PackageShared is a directory row that several packages claim. The
	// first name is a citation, not the tree's owner.
	PackageShared bool
	// CTime is the inode's change time in Unix seconds. Userland cannot set
	// it, so it separates an object the artifact shipped from one introduced
	// after the artifact.
	CTime int64
	// Inode identifies the object across renames on one filesystem.
	Inode uint64
	// Caps is the security.capability xattr being present: the file grants a
	// capability to whoever executes it.
	Caps bool
}

// Facts is one path's provenance. Path is what the caller asked about, Real is
// the path after symlinks; a symlink whose target cannot be resolved keeps Path
// as Real and reports Link. The facts that name a tree come in pairs: the
// lexical ones (Path*) describe the path as named, the bare ones describe the
// resolved target. They differ only when a link points across trees, and that
// difference is what a startup-layer escape is made of.
type Facts struct {
	Path string
	Real string
	Kind Kind
	Link bool
	Mode fs.FileMode
	// Owner and Group are the resolved file's; -1 when nothing was read.
	Owner int
	Group int
	// RootOwned is owner uid 0.
	RootOwned bool
	// Writable is group or other write permission on the resolved file.
	Writable bool
	// ParentWritable is whether a non-sticky directory above the resolved path
	// is writable by someone who is not root (an owner other than root with the
	// owner bit, or any group/other write bit). ParentOpen is the narrower
	// group/other-write fact.
	ParentWritable bool
	ParentOpen     bool
	// Executable is a regular file with an execute bit.
	Executable bool
	// Hidden is a dot-led component in the resolved path; PathHidden is one in
	// the path as named.
	Hidden     bool
	PathHidden bool
	// AdminLayer is the resolved path under an administrator-writable startup or
	// application tree; PathAdmin is the lexical path under one.
	AdminLayer bool
	PathAdmin  bool
	// Setuid is the resolved file's setuid bit: the image runs with the file
	// owner's authority, not the caller's. Setgid is the same for the group.
	Setuid bool
	Setgid bool
	// Package is the package that owns the resolved path; empty with
	// PackageKnown true means no package owns it, and Diverted says the
	// database knows the path as a local diversion.
	Package       string
	PackageKnown  bool
	Diverted      bool
	PackageShared bool
	// CTime is the resolved inode's change time in Unix seconds, and Inode is
	// its number. Both are zero when the kernel could not state them.
	CTime int64
	Inode uint64
	// Caps reports a file capability on the resolved file.
	Caps bool
}

// startupTreeRow is one row of the startupTree table.
type startupTreeRow struct {
	dir     string
	admin   bool
	startup bool
}

// startupTree is the one table of the trees the startup collector reads: the
// first flag marks a tree an administrator installs into or edits (an
// AdminLayer), the second a tree a boot, login or device event reads (a
// StartupRoot). AdminLayers and StartupRoots derive from it, so the two
// vocabularies cannot drift and a new collector path has one row to add.
// Per-user home files are not rows: a home tree holds many non-startup files,
// so those paths answer through startupHomeFiles instead.
var startupTree = []startupTreeRow{
	// systemd: the admin layers shadow the vendor layers, and the generators
	// run before the units they synthesize.
	{"/etc/systemd/system", true, true},
	{"/run/systemd/system", true, true},
	{"/usr/local/lib/systemd/system", true, true},
	{"/usr/lib/systemd/system", false, true},
	{"/lib/systemd/system", false, true},
	{"/etc/systemd/user", true, true},
	{"/root/.config/systemd/user", true, true},
	{"/etc/systemd/system-generators", true, true},
	{"/run/systemd/system-generators", true, true},
	{"/usr/local/lib/systemd/system-generators", true, true},
	{"/usr/lib/systemd/system-generators", false, true},
	{"/lib/systemd/system-generators", false, true},
	{"/etc/systemd/user-generators", true, true},
	{"/run/systemd/user-generators", true, true},
	{"/usr/local/lib/systemd/user-generators", true, true},
	{"/usr/lib/systemd/user-generators", false, true},

	// login and interactive-shell files.
	{"/etc/profile", true, true},
	{"/etc/profile.d", true, true},
	{"/etc/bash.bashrc", true, true},
	{"/etc/bashrc", true, true},
	{"/etc/bash.bash_logout", true, true},
	{"/etc/environment", true, true},
	{"/etc/zsh", true, true},
	{"/etc/fish", true, true},
	{"/etc/skel", true, true},

	// scheduled surfaces: the tables, the drop-ins, the run-parts directories
	// and both spools.
	{"/etc/crontab", true, true},
	{"/etc/anacrontab", true, true},
	{"/etc/cron.d", true, true},
	{"/etc/cron.daily", true, true},
	{"/etc/cron.hourly", true, true},
	{"/etc/cron.weekly", true, true},
	{"/etc/cron.monthly", true, true},
	{"/var/spool/cron", true, true},
	{"/var/spool/at", true, true},

	// SysV boot: the scripts, the classic hooks and the runlevel link
	// directories whose S-links enable a script.
	{"/etc/rc.local", true, true},
	{"/etc/init.d", true, true},
	{"/etc/rc.d", true, true},
	{"/etc/init.sh", true, true},
	{"/etc/rc0.d", true, true},
	{"/etc/rc1.d", true, true},
	{"/etc/rc2.d", true, true},
	{"/etc/rc3.d", true, true},
	{"/etc/rc4.d", true, true},
	{"/etc/rc5.d", true, true},
	{"/etc/rc6.d", true, true},
	{"/etc/rcS.d", true, true},

	// dynamic loader: the preload list is an administrator's file; the cache
	// is ldconfig's output, read by every process.
	{"/etc/ld.so.preload", true, true},
	{"/etc/ld.so.cache", false, true},

	// device events.
	{"/etc/udev/rules.d", true, true},
	{"/run/udev/rules.d", true, true},

	// process supervisors, the internet superservers and container
	// entrypoints.
	{"/etc/supervisor", true, true},
	{"/etc/supervisord.conf", true, true},
	{"/etc/supervisord.d", true, true},
	{"/etc/services.d", true, true},
	{"/etc/s6", true, true},
	{"/etc/s6-overlay", true, true},
	{"/etc/runit", true, true},
	{"/etc/xinetd.conf", true, true},
	{"/etc/xinetd.d", true, true},
	{"/docker-entrypoint.d", true, true},
	{"/docker-entrypoint-initdb.d", true, true},
	{"/entrypoint.d", true, true},

	// session autostart.
	{"/etc/xdg/autostart", true, true},

	// the login banner.
	{"/etc/motd", true, true},
	{"/etc/update-motd.d", true, true},

	// PAM stacks, ssh program hooks and the apt hooks apt runs as root.
	{"/etc/pam.d", true, true},
	{"/etc/ssh", true, true},
	{"/etc/apt/apt.conf", true, true},
	{"/etc/apt/apt.conf.d", true, true},

	// modprobe configuration layers.
	{"/etc/modprobe.d", true, true},
	{"/run/modprobe.d", true, true},
	{"/usr/local/lib/modprobe.d", true, true},

	// the boot and name-resolution tables the kernel and libc read by
	// position.
	{"/etc/fstab", true, true},
	{"/etc/crypttab", true, true},
	{"/etc/nsswitch.conf", true, true},
	{"/etc/hosts.allow", true, true},
	{"/etc/hosts.deny", true, true},

	// application trees an administrator installs into; nothing a boot or a
	// login reads by position lives here, but a payload does.
	{"/opt", true, false},
	{"/srv", true, false},
	{"/var/lib", true, false},
	{"/usr/local", true, false},
	{"/etc/ld.so.conf", true, false},
	{"/etc/ld.so.conf.d", true, false},
}

// AdminLayers are the trees an administrator installs into or edits. A target
// here is not untrusted by itself; it is outside the distribution's provenance
// and needs the package check to tell a local build from a dropped payload.
var AdminLayers = treeRoots(func(row startupTreeRow) bool { return row.admin })

// StartupRoots are the trees whose files a boot, login or device event reads.
// A startup file's real location is expected to stay inside one of them: a
// symlink out of these trees runs bytes the surface's listing never shows.
var StartupRoots = treeRoots(func(row startupTreeRow) bool { return row.startup })

// treeRoots collects the table's dirs whose flag holds.
func treeRoots(flag func(startupTreeRow) bool) []string {
	var roots []string
	for _, row := range startupTree {
		if flag(row) {
			roots = append(roots, row.dir)
		}
	}
	return roots
}

// startupHomeFiles are the per-user files a shell reads at login or for an
// interactive session. They are named relative to /root or /home/<user> so a
// project's own .profile in a deeper directory is not a startup file.
var startupHomeFiles = []string{
	".bashrc", ".bash_profile", ".bash_login", ".profile", ".bash_logout",
	".zshrc", ".zprofile", ".zshenv", ".zlogin", ".zlogout",
	".config/fish/config.fish",
}

// PackageResolver answers package ownership: the package that owns a path,
// with known=false when the question could not be answered. *prov.Catalog is
// the live implementation; tests and callers that only read facts can pass a
// fake.
type PackageResolver interface {
	Owned(path string) (pkg string, known bool)
}

// Build reads the facts a set of raw attributes states. It is the one place
// the tree vocabularies are applied, so every caller classifies a host the
// same way.
func Build(path string, attrs Attrs) Facts {
	facts := Facts{
		Path:           path,
		Real:           attrs.Real,
		Kind:           attrs.Kind,
		Link:           attrs.Link,
		Mode:           attrs.Mode,
		Owner:          attrs.UID,
		Group:          attrs.GID,
		ParentWritable: attrs.ParentWritable,
		ParentOpen:     attrs.ParentOpen,
		Package:        attrs.Package,
		PackageKnown:   attrs.PackageKnown,
		Diverted:       attrs.Diverted,
		PackageShared:  attrs.PackageShared,
		CTime:          attrs.CTime,
		Inode:          attrs.Inode,
		Caps:           attrs.Caps,
	}
	if facts.Real == "" {
		facts.Real = path
	}
	facts.PathHidden = HiddenPath(path)
	facts.PathAdmin = UnderAny(path, AdminLayers)
	facts.Hidden = HiddenPath(facts.Real)
	facts.AdminLayer = UnderAny(facts.Real, AdminLayers)
	facts.RootOwned = facts.Owner == 0
	facts.Writable = facts.Mode.Perm()&0o022 != 0
	bits := uint32(facts.Mode)
	facts.Setuid = facts.Mode&os.ModeSetuid != 0 || bits&0o4000 != 0
	facts.Setgid = facts.Mode&os.ModeSetgid != 0 || bits&0o2000 != 0
	facts.Executable = facts.Kind == File && facts.Mode.Perm()&0o111 != 0
	return facts
}

// Classify reads one path's facts. A nil resolver reports package ownership as
// unknown; a path that does not exist still carries the path-level facts
// (hidden, admin layer, package ownership of a deleted package file).
type dirFlags struct {
	replaceable bool
	open        bool
}

// Classifier is one run's fact reader. It shares the directory-metadata cache
// across paths, so a tree of files costs one stat per directory rather than
// one per path.
type Classifier struct {
	resolver PackageResolver
	dirs     map[string]dirFlags
	facts    map[string]Facts
}

func NewClassifier(resolver PackageResolver) *Classifier {
	return &Classifier{resolver: resolver, dirs: map[string]dirFlags{}, facts: map[string]Facts{}}
}

func (c *Classifier) Classify(path string) Facts {
	if facts, ok := c.facts[path]; ok {
		return facts
	}
	facts := classify(path, c.resolver, c.dirs)
	c.facts[path] = facts
	return facts
}

func Classify(path string, resolver PackageResolver) Facts {
	return classify(path, resolver, nil)
}

func classify(path string, resolver PackageResolver, dirs map[string]dirFlags) Facts {
	attrs := Attrs{Kind: Missing, UID: -1, GID: -1, Real: path}
	if path == "" {
		return Build(path, attrs)
	}

	info, err := os.Lstat(path)
	if err == nil {
		attrs.Link = info.Mode()&os.ModeSymlink != 0
		// The whole path is resolved, not only a link in its last component:
		// on a usrmerge host /bin is a link to /usr/bin, and the package
		// database records the spelling the file was installed under.
		if real, err := filepath.EvalSymlinks(path); err == nil && real != "" {
			attrs.Real = real
		}
		target, err := os.Stat(attrs.Real)
		if err == nil {
			attrs.Kind = kindOf(target.Mode())
			attrs.Mode = target.Mode()
			attrs.UID, attrs.GID = statOwner(target)
			attrs.CTime, attrs.Inode = statMeta(target)
			attrs.Caps = fileCaps(attrs.Real)
		} else {
			attrs.Kind = Missing
		}
	}

	attrs.ParentWritable, attrs.ParentOpen = parentFlags(attrs.Real, dirs)
	if resolver != nil {
		attrs.Package, attrs.PackageKnown, attrs.PackageShared = owned(resolver, attrs.Real)
		if attrs.Real != path && !attrs.PackageKnown {
			// A database that records the spelling the file was installed
			// under, or one that could not answer for the resolved path, still
			// gets the caller's spelling as a second question. A known-empty
			// answer for the real file is the dropped-binary fact and stands.
			attrs.Package, attrs.PackageKnown, attrs.PackageShared = owned(resolver, path)
		}
		if div, ok := resolver.(diversionResolver); ok {
			attrs.Diverted = div.Diversion(attrs.Real) || (attrs.Real != path && div.Diversion(path))
		}
	}
	return Build(path, attrs)
}

// diversionResolver is a package database that also answers diversions.
// *prov.Catalog is the live implementation.
type diversionResolver interface {
	Diversion(path string) bool
}

// sharedResolver is a resolver that can say a directory row lists several
// packages. A single package resolver is still a valid answer.
type sharedResolver interface {
	OwnedShared(path string) (string, bool, bool)
}

func owned(resolver PackageResolver, path string) (string, bool, bool) {
	if shared, ok := resolver.(sharedResolver); ok {
		return shared.OwnedShared(path)
	}
	pkg, known := resolver.Owned(path)
	return pkg, known, false
}

// Owner reads a file's uid from its FileInfo. It is -1 when the platform
// cannot state one.
func Owner(info fs.FileInfo) int {
	owner, _ := statOwner(info)
	return owner
}

func kindOf(mode fs.FileMode) Kind {
	switch {
	case mode.IsRegular():
		return File
	case mode.IsDir():
		return Dir
	}
	return Other
}

// parentFlags walks the path's directory chain once and states both facts a
// trigger can be replaced by: `replaceable` (a non-root owner with the owner
// bit, or group/other write) and `open` (group/other write alone). A sticky
// directory is protected from everyone but the file's owner, which is what
// /tmp is for.
func parentFlags(path string, cache map[string]dirFlags) (replaceable, open bool) {
	for dir := filepath.Dir(path); ; {
		flags, ok := cache[dir]
		if !ok {
			flags = statDirFlags(dir)
			if cache != nil {
				cache[dir] = flags
			}
		}
		replaceable = replaceable || flags.replaceable
		open = open || flags.open
		parent := filepath.Dir(dir)
		if parent == dir {
			return replaceable, open
		}
		dir = parent
	}
}

func statDirFlags(dir string) dirFlags {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSticky != 0 {
		return dirFlags{}
	}
	perm := info.Mode().Perm()
	flags := dirFlags{open: perm&0o022 != 0}
	if flags.open {
		flags.replaceable = true
	}
	if owner, _ := statOwner(info); owner != 0 && perm&0o200 != 0 {
		flags.replaceable = true
	}
	return flags
}

// SkelTemplate reports whether path is one of the login files /etc/skel
// installs into a new home. Their leading dots are the normal shape of a home
// dotfile, so an administrator tree does not make them hidden triggers.
func SkelTemplate(path string) bool {
	rest, ok := strings.CutPrefix(path, "/etc/skel/")
	if !ok {
		return false
	}
	for _, name := range startupHomeFiles {
		if rest == name {
			return true
		}
	}
	return false
}

// StartupPath reports whether path is one of the files a boot, login or device
// event reads: under a startup tree, or one of the shell's own per-user files.
func StartupPath(path string) bool {
	if UnderAny(path, StartupRoots) {
		return true
	}
	rest, ok := strings.CutPrefix(path, "/root/")
	if !ok {
		home, found := strings.CutPrefix(path, "/home/")
		if !found {
			return false
		}
		_, tail, found := strings.Cut(home, "/")
		if !found {
			return false
		}
		rest = tail
	}
	for _, name := range startupHomeFiles {
		if rest == name {
			return true
		}
	}
	return strings.HasPrefix(rest, ".config/fish/conf.d/") && strings.HasSuffix(rest, ".fish")
}

// UnderAny reports whether path is one of roots or inside one, on a path
// boundary: /optfoo is not under /opt.

// UsrVariants answers the two absolute spellings usrmerge creates for one
// path: the asked spelling and its counterpart across the /usr merge point.
// The package database, the content ledger and the active-object set all
// match files under both spellings through this one pair, so a lookup cannot
// agree under one spelling and miss under the other.
func UsrVariants(path string) []string {
	if path == "" {
		return nil
	}
	if rest, ok := strings.CutPrefix(path, "/usr/"); ok {
		return []string{path, "/" + rest}
	}
	if path == "/" || path == "/usr" {
		return []string{path}
	}
	return []string{path, "/usr" + path}
}

func UnderAny(path string, roots []string) bool {
	for _, root := range roots {
		if Under(path, root) {
			return true
		}
	}
	return false
}

// Under reports whether path is root or inside root, on a path boundary.
func Under(path, root string) bool {
	if root == "/" {
		return strings.HasPrefix(path, "/")
	}
	if path == root {
		return true
	}
	if !strings.HasPrefix(path, root) {
		return false
	}
	return strings.HasPrefix(path[len(root):], "/")
}

// HiddenPath reports whether any component below the root starts with a dot.
func HiddenPath(path string) bool {
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if len(part) > 1 && part[0] == '.' {
			return true
		}
	}
	return false
}
