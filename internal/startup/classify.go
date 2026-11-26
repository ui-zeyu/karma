package startup

import (
	"strings"

	"karma/internal/trust"
)

// classifyPath maps a collected path to its surface and dialect. The native
// collector fills File with it after reading; the path vocabularies live here
// so the surfaces cannot drift from the parsers.
func classifyPath(path string) (Surface, Dialect) {
	for _, surface := range surfaceRuns {
		if surface.match == nil || !surface.match(path) {
			continue
		}
		return Surface(surface.name), surface.dialect(path)
	}
	return SurfaceSystemd, systemdDialect(path)
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

// isCronPath names the scheduled surfaces.
func isCronPath(path string) bool {
	switch path {
	case "/etc/crontab", "/etc/anacrontab":
		return true
	}
	for _, prefix := range []string{
		"/etc/cron.d/", "/var/spool/cron/",
		"/etc/cron.daily/", "/etc/cron.hourly/", "/etc/cron.weekly/", "/etc/cron.monthly/",
		"/var/spool/at/",
	} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// isInitPath names the SysV boot scripts and the two classic boot hooks.
func isInitPath(path string) bool {
	switch path {
	case "/etc/rc.local", "/etc/rc.d/rc.local", "/etc/init.sh":
		return true
	}
	return strings.HasPrefix(path, "/etc/init.d/")
}

func isLoaderPath(path string) bool {
	return path == "/etc/ld.so.preload" || path == "/etc/ld.so.cache"
}

func isUdevPath(path string) bool {
	return strings.HasPrefix(path, "/etc/udev/rules.d/") ||
		strings.HasPrefix(path, "/run/udev/rules.d/")
}

func isPAMPath(path string) bool {
	return strings.HasPrefix(path, "/etc/pam.d/") || isMotdPath(path)
}

// isMotdPath names the login banner's run-parts directory.
func isMotdPath(path string) bool {
	return strings.HasPrefix(path, "/etc/update-motd.d/")
}

func isSystemPath(path string) bool {
	switch path {
	case "/etc/fstab", "/etc/crypttab", "/etc/nsswitch.conf",
		"/etc/hosts.allow", "/etc/hosts.deny":
		return true
	}
	return false
}

func isGeneratorPath(path string) bool {
	for _, dir := range append(append([]string(nil), generatorDirs...), userGeneratorDirs...) {
		if strings.HasPrefix(path, dir+"/") {
			return true
		}
	}
	return false
}

func isSupervisorPath(path string) bool {
	if isXinetdPath(path) {
		return true
	}
	for _, prefix := range []string{
		"/etc/supervisor/", "/etc/supervisord.conf", "/etc/supervisord.d/",
		"/etc/s6/", "/etc/services.d/", "/etc/s6-overlay/",
		"/docker-entrypoint.d/", "/docker-entrypoint-initdb.d/", "/entrypoint.d/",
	} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// isXinetdPath names the internet superserver's configuration layers.
func isXinetdPath(path string) bool {
	return path == "/etc/xinetd.conf" || strings.HasPrefix(path, "/etc/xinetd.d/")
}

func isXdgPath(path string) bool {
	if strings.HasPrefix(path, "/etc/xdg/autostart/") ||
		strings.HasPrefix(path, "/root/.config/autostart/") {
		return true
	}
	return strings.HasPrefix(path, "/home/") && strings.Contains(path, "/.config/autostart/")
}

func isAptPath(path string) bool {
	return path == "/etc/apt/apt.conf" || strings.HasPrefix(path, "/etc/apt/apt.conf.d/")
}

func isModulePath(path string) bool {
	return strings.HasPrefix(path, "/etc/modprobe.d/") ||
		strings.HasPrefix(path, "/run/modprobe.d/") ||
		strings.HasPrefix(path, "/usr/local/lib/modprobe.d/")
}
