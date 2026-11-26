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
	// owner with the owner bit. PathParentWritable is the same question for the
	// path as it was named, which is where a symlink itself can be replaced.
	// ParentOpen is the narrower fact — group/other write alone — and is what a
	// user-owned surface must be judged by; PathParentOpen is its lexical pair.
	ParentWritable     bool
	ParentOpen         bool
	PathParentWritable bool
	PathParentOpen     bool
	Package            string
	PackageKnown       bool
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
	// group/other-write fact. PathParentWritable and PathParentOpen ask the same
	// about the path as named, so a link inside a writable directory is
	// replaceable even when its target is not.
	ParentWritable     bool
	ParentOpen         bool
	PathParentWritable bool
	PathParentOpen     bool
	// Executable is a regular file with an execute bit.
	Executable bool
	// Hidden is a dot-led component in the resolved path; PathHidden is one in
	// the path as named.
	Hidden     bool
	PathHidden bool
	// TrustedRoot is the resolved path under a distribution program or library
	// tree.
	TrustedRoot bool
	// AdminLayer is the resolved path under an administrator-writable startup or
	// application tree; PathAdmin is the lexical path under one.
	AdminLayer bool
	PathAdmin  bool
	// Startup is the resolved path being a startup surface; PathStartup is the
	// lexical path being one.
	Startup     bool
	PathStartup bool
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

// TrustedRoots are the trees a distribution owns end to end. A file here that
// the package database does not carry is a different fact (unowned-files), not
// an administrator's install.
var TrustedRoots = []string{
	"/bin", "/sbin", "/usr/bin", "/usr/sbin",
	"/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/libexec",
	"/lib/systemd/system", "/usr/lib/systemd/system",
}

// AdminLayers are the trees an administrator installs into or edits. A target
// here is not untrusted by itself; it is outside the distribution's provenance
// and needs the package check to tell a local build from a dropped payload.
var AdminLayers = []string{
	"/etc/profile", "/etc/profile.d", "/etc/bash.bashrc", "/etc/bashrc",
	"/etc/bash.bash_logout", "/etc/environment", "/etc/zsh", "/etc/fish",
	"/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system",
	"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly",
	"/etc/cron.monthly", "/var/spool/cron", "/etc/crontab", "/etc/anacrontab",
	"/etc/rc.local", "/etc/init.d", "/etc/rc.d",
	"/etc/udev/rules.d", "/run/udev/rules.d",
	"/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d",
	"/etc/supervisor", "/etc/supervisord.conf", "/etc/s6", "/etc/runit",
	"/etc/apt/apt.conf.d", "/etc/pam.d", "/etc/ssh",
	"/etc/xdg/autostart", "/etc/motd", "/etc/update-motd.d", "/etc/skel",
	"/opt", "/srv", "/var/lib", "/usr/local",
}

// StartupRoots are the trees whose files a boot, login or device event reads.
// A startup file's real location is expected to stay inside one of them: a
// symlink out of these trees runs bytes the surface's listing never shows.
var StartupRoots = []string{
	"/etc/systemd", "/run/systemd", "/usr/local/lib/systemd",
	"/usr/lib/systemd", "/lib/systemd",
	"/etc/profile", "/etc/profile.d", "/etc/bash.bashrc", "/etc/bashrc",
	"/etc/bash.bash_logout", "/etc/zsh", "/etc/fish", "/etc/environment",
	"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly",
	"/etc/cron.monthly", "/var/spool/cron", "/etc/crontab", "/etc/anacrontab",
	"/etc/rc.local", "/etc/init.d", "/etc/rc.d", "/etc/rcS.d",
	"/etc/udev/rules.d", "/run/udev/rules.d",
	"/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d",
	"/etc/supervisor", "/etc/s6", "/etc/runit",
	"/etc/apt/apt.conf.d", "/etc/pam.d", "/etc/ssh", "/etc/xdg/autostart",
	"/etc/motd", "/etc/update-motd.d", "/etc/skel",
}

// startupHomeFiles are the per-user files a shell reads at login or for an
// interactive session. They are named relative to /root or /home/<user> so a
// project's own .profile in a deeper directory is not a startup file.
var startupHomeFiles = []string{
	".bashrc", ".bash_profile", ".bash_login", ".profile", ".bash_logout",
	".zshrc", ".zprofile", ".zshenv", ".zlogin",
	".config/fish/config.fish",
}

// PackageResolver answers package ownership: the package that owns a path,
// with known=false when the question could not be answered. *Resolver is the
// live implementation; tests and callers that only read facts can pass a fake.
type PackageResolver interface {
	Owned(path string) (pkg string, known bool)
}

// Build reads the facts a set of raw attributes states. It is the one place
// the tree vocabularies are applied, so every caller classifies a host the
// same way.
func Build(path string, attrs Attrs) Facts {
	facts := Facts{
		Path:               path,
		Real:               attrs.Real,
		Kind:               attrs.Kind,
		Link:               attrs.Link,
		Mode:               attrs.Mode,
		Owner:              attrs.UID,
		Group:              attrs.GID,
		ParentWritable:     attrs.ParentWritable,
		ParentOpen:         attrs.ParentOpen,
		PathParentWritable: attrs.PathParentWritable,
		PathParentOpen:     attrs.PathParentOpen,
		Package:            attrs.Package,
		PackageKnown:       attrs.PackageKnown,
		Diverted:           attrs.Diverted,
		PackageShared:      attrs.PackageShared,
		CTime:              attrs.CTime,
		Inode:              attrs.Inode,
		Caps:               attrs.Caps,
	}
	if facts.Real == "" {
		facts.Real = path
	}
	facts.PathHidden = HiddenPath(path)
	facts.PathAdmin = UnderAny(path, AdminLayers)
	facts.PathStartup = StartupPath(path)
	facts.Hidden = HiddenPath(facts.Real)
	facts.AdminLayer = UnderAny(facts.Real, AdminLayers)
	facts.TrustedRoot = UnderAny(facts.Real, TrustedRoots)
	facts.Startup = StartupPath(facts.Real)
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
func Classify(path string, resolver PackageResolver) Facts {
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

	attrs.ParentWritable, attrs.ParentOpen = parentFlags(attrs.Real)
	attrs.PathParentWritable, attrs.PathParentOpen = parentFlags(path)
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
func parentFlags(path string) (replaceable, open bool) {
	for dir := filepath.Dir(path); ; {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			mode := info.Mode()
			if mode&os.ModeSticky == 0 {
				perm := mode.Perm()
				if perm&0o022 != 0 {
					open = true
					replaceable = true
				}
				owner, _ := statOwner(info)
				if owner != 0 && perm&0o200 != 0 {
					replaceable = true
				}
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return replaceable, open
		}
		dir = parent
	}
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
	return false
}

// UnderAny reports whether path is one of roots or inside one, on a path
// boundary: /optfoo is not under /opt.
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
