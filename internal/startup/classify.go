package startup

import (
	"strings"

	"karma/internal/trust"
)

// classifyPath maps a collected path to its surface and dialect. The native
// collector fills File with it after reading; the path vocabularies live here
// so the surfaces cannot drift from the parsers.
func classifyPath(path string) (Surface, Dialect) {
	return surfaceFor(path), dialectFor(path)
}

func surfaceFor(path string) Surface {
	switch {
	case isProfilePath(path):
		return SurfaceProfile
	case isInitPath(path):
		return SurfaceInit
	case isCronPath(path):
		return SurfaceCron
	case isLoaderPath(path):
		return SurfaceLoader
	case isUdevPath(path):
		return SurfaceUdev
	case isSSHPath(path):
		return SurfaceSSH
	case isPAMPath(path):
		return SurfacePAM
	case isSupervisorPath(path):
		return SurfaceSupervisor
	case isXdgPath(path):
		return SurfaceXdg
	case isAptPath(path):
		return SurfaceApt
	case isModulePath(path):
		return SurfaceModule
	}
	return SurfaceSystemd
}

func dialectFor(path string) Dialect {
	switch {
	case path == "/etc/environment":
		return EnvDialect
	case isLoaderPath(path):
		return LoaderDialect
	case isUdevPath(path):
		return UdevDialect
	case isInitPath(path):
		return ShellDialect
	case isCronPath(path):
		if isCronShellPath(path) {
			return ShellDialect
		}
		return CronDialect
	case isSSHPath(path):
		return sshDialect(path)
	case isPAMPath(path):
		return PAMDialect
	case isSupervisorPath(path):
		if strings.HasSuffix(path, ".conf") || strings.HasSuffix(path, ".ini") {
			return UnitDialect
		}
		return ShellDialect
	case isXdgPath(path):
		return UnitDialect
	case isAptPath(path):
		return AptDialect
	case isModulePath(path):
		return ModprobeDialect
	case isProfilePath(path):
		return ShellDialect
	}
	return UnitDialect
}

// isProfilePath names the login and interactive-shell surfaces. A user's unit
// tree lives under /home too, so the home half asks trust.StartupPath rather
// than the directory alone.
func isProfilePath(path string) bool {
	switch path {
	case "/etc/profile", "/etc/bash.bashrc", "/etc/bashrc", "/etc/bash.bash_logout", "/etc/environment":
		return true
	}
	if strings.HasPrefix(path, "/etc/profile.d/") || strings.HasPrefix(path, "/etc/zsh/") {
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
	return path == "/etc/ld.so.preload"
}

func isUdevPath(path string) bool {
	return strings.HasPrefix(path, "/etc/udev/rules.d/") ||
		strings.HasPrefix(path, "/run/udev/rules.d/")
}

func isPAMPath(path string) bool {
	return strings.HasPrefix(path, "/etc/pam.d/")
}

func isSupervisorPath(path string) bool {
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
