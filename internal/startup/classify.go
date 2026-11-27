package startup

import (
	"path/filepath"
	"strings"

	"karma/internal/trust"
)

// classifyPath maps a collected path to its surface and dialect. The matchers
// derive from the same pattern lists the collectors glob (surfaceRun.compiled,
// built once in init), so a collected file classifies as what collected it by
// construction; the custom matches are the surfaces whose vocabulary is
// semantics rather than globs (profile homes, PAM's motd, systemd units). ok
// answers whether any surface claimed the path — a collected file no surface
// claims is the drift this function exists to surface.
func classifyPath(path string) (Surface, Dialect, bool) {
	for _, surface := range surfaceRuns {
		if !surface.matches(path) {
			continue
		}
		return Surface(surface.name), surface.dialect(path), true
	}
	return SurfaceSystemd, systemdDialect(path), false
}

// compilePattern turns one collector glob into a matcher. The grammar is the
// small one the lists use: a literal path, a trailing or mid-path `*`
// segment, and a suffix glob such as `*.sh` inside one segment.
func compilePattern(pattern string) func(string) bool {
	segs := strings.Split(strings.Trim(pattern, "/"), "/")
	return func(path string) bool {
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) != len(segs) {
			return false
		}
		for i, seg := range segs {
			if !matchSegment(seg, parts[i]) {
				return false
			}
		}
		return true
	}
}

// matchSegment matches one path segment against one glob segment.
func matchSegment(seg, part string) bool {
	star := strings.IndexByte(seg, '*')
	if star < 0 {
		return seg == part
	}
	prefix, suffix := seg[:star], seg[star+1:]
	return len(part) >= len(prefix)+len(suffix) &&
		strings.HasPrefix(part, prefix) && strings.HasSuffix(part, suffix)
}

// generatorSearchDirs are every generator directory the systemd surface reads.
var generatorSearchDirs = append(append([]string(nil), generatorDirs...), userGeneratorDirs...)

// isSystemdUnitPath names the files the systemd surface collects: unit files,
// their drop-ins, and the generators.
func isSystemdUnitPath(path string) bool {
	base := filepath.Base(path)
	if IsUnitName(base) {
		return true
	}
	if strings.HasSuffix(base, ".conf") {
		dir := filepath.Base(filepath.Dir(path))
		if strings.HasSuffix(dir, ".d") && IsUnitName(strings.TrimSuffix(dir, ".d")) {
			return true
		}
	}
	return isGeneratorPath(path)
}

func systemdDialect(path string) Dialect {
	if isGeneratorPath(path) {
		return GeneratorsDialect
	}
	return UnitDialect
}

func profileDialect(path string) Dialect {
	if path == "/etc/environment" {
		return EnvDialect
	}
	return ShellDialect
}

func cronDialect(path string) Dialect {
	if isCronShellPath(path) {
		return ShellDialect
	}
	return CronDialect
}

func pamDialect(path string) Dialect {
	if isMotdPath(path) {
		return ShellDialect
	}
	return PAMDialect
}

func supervisorDialect(path string) Dialect {
	if isXinetdPath(path) {
		return XinetdDialect
	}
	if strings.HasSuffix(path, ".conf") || strings.HasSuffix(path, ".ini") {
		return UnitDialect
	}
	return ShellDialect
}

// isProfilePath names the login and interactive-shell surfaces. A user's unit
// tree lives under /home too, so the home half asks trust.StartupPath rather
// than the directory alone.
func isProfilePath(path string) bool {
	switch path {
	case "/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/bash.bash_logout", "/etc/environment":
		return true
	}
	if strings.HasPrefix(path, "/etc/profile.d/") || strings.HasPrefix(path, "/etc/zsh/") ||
		strings.HasPrefix(path, "/etc/fish/") {
		return true
	}
	if trust.SkelTemplate(path) {
		return true
	}
	if strings.HasPrefix(path, "/root/") || strings.HasPrefix(path, "/home/") {
		return trust.StartupPath(path)
	}
	return false
}

func isPAMPath(path string) bool {
	return strings.HasPrefix(path, "/etc/pam.d/") || isMotdPath(path)
}

// isMotdPath names the login banner's run-parts directory.
func isMotdPath(path string) bool {
	return strings.HasPrefix(path, "/etc/update-motd.d/")
}

func isGeneratorPath(path string) bool {
	for _, dir := range generatorSearchDirs {
		if strings.HasPrefix(path, dir+"/") {
			return true
		}
	}
	return false
}

// isXinetdPath names the internet superserver's configuration layers.
func isXinetdPath(path string) bool {
	return path == "/etc/xinetd.conf" || strings.HasPrefix(path, "/etc/xinetd.d/")
}
