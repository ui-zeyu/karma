package audit

import (
	"bytes"
	"context"
	"debug/elf"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"karma/internal/trust"
)

// authorityFiles are the objects whose content grants authority without being
// executed by name: the sudo policy, the account databases, the host's own ssh
// keys, and root's authorized keys.
var authorityFiles = []string{
	"/etc/sudoers",
	"/etc/sudoers.d/*",
	"/etc/passwd",
	"/etc/shadow",
	"/etc/ssh/ssh_host_*_key",
}

// authorityRoots are walked for setuid and file-capability objects. The
// distribution's program trees and the administrator's install trees are the
// places an execution can acquire an authority the caller did not have.
var authorityRoots = []string{
	// High-signal drop trees first: a planted setuid payload usually lands
	// here, and a per-root budget keeps the distribution's library tree from
	// spending the whole walk before these are read.
	"/home", "/root", "/srv", "/var/tmp", "/var/www", "/var/spool", "/tmp", "/dev/shm",
	"/usr/local", "/opt", "/etc",
	"/usr/libexec", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/lib",
}

// authoritySkip keeps the walk out of trees that carry no executable
// authority and can be very large.
var authoritySkip = []string{
	"/usr/lib/modules", "/usr/lib/firmware", "/usr/lib/debug",
	"/usr/share", "/usr/lib/python", "/usr/lib/ruby", "/usr/lib/node_modules",
	"/var/lib/docker", "/var/lib/containerd", "/var/lib/lxc", "/var/lib/snapd",
	"/var/lib/flatpak", "/var/cache", "/var/log", "/var/lib/apt/lists",
	"/root/.cache",
}

// trustedAuthorityRoots are the trees an authority bit is expected in. An
// object outside them is a finding even when it predates the boundary.
var trustedAuthorityRoots = []string{
	"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec",
	"/lib", "/lib64", "/usr/lib64",
}

const (
	authorityLimit      = 300000
	authorityRootBudget = 50000
)

// authoritySkipNames keeps the walk out of administrator tool caches. A
// setuid payload there is rare; the drop trees (/tmp, /dev/shm, /usr/local,
// /opt, /home/<user>/bin) remain walked.
var authoritySkipNames = map[string]bool{
	".cache": true, ".npm": true, ".cargo": true, ".rustup": true,
	".vscode-server": true, ".kimi-code": true, "node_modules": true,
	"site-packages": true, "dist-packages": true, ".git": true,
}

// authorityBit names the bits one object carries, for the finding chain.
func authorityBit(facts trust.Facts) string {
	var bits []string
	if facts.Setuid {
		bits = append(bits, "setuid")
	}
	if facts.Setgid {
		bits = append(bits, "setgid")
	}
	if facts.Caps {
		bits = append(bits, "file capabilities")
	}
	if len(bits) == 0 {
		return "no authority bit"
	}
	return strings.Join(bits, "+")
}

// unusualAuthorityBinary reports an authority object that is not an ELF
// executable or names an interpreter outside the loader's own trees. A
// setuid script is ignored by Linux, and a custom PT_INTERP is a rootkit
// shape that a hash match on the old file would not explain.
func unusualAuthorityBinary(path string, facts trust.Facts) (bool, string) {
	if facts.Kind != trust.File {
		return false, ""
	}
	file, err := elf.Open(path)
	if err != nil {
		return true, "not an ELF executable"
	}
	defer file.Close()
	for _, program := range file.Progs {
		if program.Type != elf.PT_INTERP {
			continue
		}
		reader := program.Open()
		data, err := io.ReadAll(io.LimitReader(reader, 4096))
		if err != nil || len(data) == 0 {
			return true, "executable names an unreadable program interpreter"
		}
		interp := string(bytes.TrimRight(data, "\x00"))
		if !trustedProgramInterpreter(interp) {
			return true, "program interpreter " + interp
		}
	}
	return false, ""
}

func trustedProgramInterpreter(path string) bool {
	if !underAny(path, []string{"/lib", "/lib64", "/usr/lib", "/usr/lib64"}) {
		return false
	}
	base := filepath.Base(path)
	return strings.HasPrefix(base, "ld-") || strings.HasPrefix(base, "ld-linux") ||
		strings.HasPrefix(base, "ld-musl") || strings.HasPrefix(base, "ld64")
}

func collectAuthority(ctx context.Context, filter Filter) ([]string, []string) {
	seen := map[string]bool{}
	var paths []string
	add := func(path string) {
		if path == "" || seen[path] || !filter.touchesPath(path) {
			return
		}
		seen[path] = true
		paths = append(paths, path)
	}
	for _, pattern := range authorityFiles {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, path := range matches {
			if pathInScope(path, filter) {
				add(path)
			}
		}
	}
	var gaps []string
	visited := 0
	for _, root := range authorityRoots {
		if err := ctx.Err(); err != nil {
			break
		}
		if !filter.touchesPath(root) {
			continue
		}
		if _, err := os.Stat(root); err != nil {
			continue
		}
		rootVisited := 0
		stopped := false
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if err := ctx.Err(); err != nil {
				return filepath.SkipAll
			}
			if entry.IsDir() {
				if !filter.touchesPath(path) {
					return filepath.SkipDir
				}
				if authoritySkipNames[entry.Name()] {
					return filepath.SkipDir
				}
				for _, skip := range authoritySkip {
					if path == skip {
						return filepath.SkipDir
					}
				}
				return nil
			}
			if visited >= authorityLimit || rootVisited >= authorityRootBudget {
				stopped = true
				return filepath.SkipAll
			}
			visited++
			rootVisited++
			if entry.Type()&os.ModeSymlink != 0 {
				return nil
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() {
				return nil
			}
			// A file capability only acts on an executable; asking the xattr on
			// every data file is the difference between seconds and a minute.
			if info.Mode()&os.ModeSetuid == 0 && info.Mode()&os.ModeSetgid == 0 &&
				(info.Mode().Perm()&0o111 == 0 || !hasCaps(path)) {
				return nil
			}
			add(path)
			return nil
		})
		if stopped {
			gaps = append(gaps, "authority walk of "+root+" stopped at its file budget")
		}
		if err != nil && ctx.Err() == nil {
			gaps = append(gaps, "authority walk of "+root+": "+err.Error())
		}
		if visited >= authorityLimit {
			gaps = append(gaps, "authority walk stopped at its file limit")
			break
		}
	}
	sort.Strings(paths)
	return paths, gaps
}
