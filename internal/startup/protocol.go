package startup

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"karma/internal/trust"
)

// The sh source sends one corpus in a line protocol. The protocol carries
// bytes the shell cannot state as fields — file contents, paths, package rows —
// through base64, so a unit description cannot forge a record boundary. The
// header states the version; every other line starts with a tag the parser
// knows, and an unknown tag is an error rather than a silently dropped file.
//
//	KARMA-STARTUP 1
//	B <path>                      the next line is the file's base64 content
//	E <path>                      the file exists but its read failed
//	L <link> <target>             one enablement symlink
//	P <path> <kind> <mode> <uid> <gid> <link> <real> <parent> <open> <path-parent> <path-open> <ctime> <inode> <caps>
//	D <0|1> / R <0|1>             whether dpkg / rpm answered the batch
//	O dpkg|rpm                    the next line is the manager's base64 output
const protocolHeader = "KARMA-STARTUP 1"

// ParseCorpus reads the sh source's protocol into the same corpus the native
// collector builds. An error means the collection itself is unusable; a file
// the target could not read is recorded so the audit can state the coverage
// gap instead of presenting a short table as complete.
func ParseCorpus(text string) (*Corpus, error) {
	lines := strings.Split(text, "\n")
	corpus := NewCorpus(nil, nil, nil)
	seen := map[string]bool{}
	attrs := map[string]trust.Attrs{}
	packages := map[string]string{}
	dpkgAnswered, rpmAnswered := false, false

	for index := 0; index < len(lines); index++ {
		line := strings.TrimSuffix(lines[index], "\r")
		if index == 0 {
			if line != protocolHeader {
				return nil, fmt.Errorf("startup corpus: header %q is not %q", line, protocolHeader)
			}
			continue
		}
		if line == "" {
			continue
		}
		tag, rest, _ := strings.Cut(line, " ")
		switch tag {
		case "B":
			path, err := decodeField(rest)
			if err != nil {
				return nil, fmt.Errorf("startup corpus line %d: %w", index+1, err)
			}
			index++
			if index >= len(lines) {
				return nil, fmt.Errorf("startup corpus line %d: B is missing its body", index)
			}
			if seen[path] {
				continue
			}
			seen[path] = true
			body, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(lines[index], "\r"))
			if err != nil {
				return nil, fmt.Errorf("startup corpus line %d: body of %q: %w", index+1, path, err)
			}
			surface, dialect := classifyPath(path)
			corpus.files = append(corpus.files, File{
				Path: path, Surface: surface, Dialect: dialect, Body: string(body),
				Unit: unitName(path), DropIn: isDropIn(path),
			})
		case "E":
			path, err := decodeField(rest)
			if err != nil {
				return nil, fmt.Errorf("startup corpus line %d: %w", index+1, err)
			}
			corpus.unreadable[path] = true
		case "L":
			fields := strings.Fields(rest)
			if len(fields) != 2 {
				return nil, fmt.Errorf("startup corpus line %d: L needs a link and a target", index+1)
			}
			link, err := decodeField(fields[0])
			if err != nil {
				return nil, fmt.Errorf("startup corpus line %d: %w", index+1, err)
			}
			name := filepath.Base(link)
			if _, ok := corpus.enabled[name]; !ok {
				corpus.enabled[name] = link
			}
			// An init link's name is S<digits><script>; the script is what the
			// analysis looks up, and the link is the enablement.
			if strings.HasPrefix(name, "S") {
				if script := strings.TrimLeft(name[1:], "0123456789"); script != "" {
					if _, ok := corpus.enabled[script]; !ok {
						corpus.enabled[script] = link
					}
				}
			}
		case "D":
			dpkgAnswered = rest == "1"
		case "R":
			rpmAnswered = rest == "1"
		case "O":
			manager := strings.TrimSpace(rest)
			index++
			if index >= len(lines) {
				return nil, fmt.Errorf("startup corpus line %d: O is missing its output", index)
			}
			body, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(lines[index], "\r"))
			if err != nil {
				return nil, fmt.Errorf("startup corpus line %d: %s output: %w", index+1, manager, err)
			}
			switch manager {
			case "dpkg":
				parseDpkgRows(string(body), packages)
			case "rpm":
				parseRPMRows(string(body), packages)
			default:
				return nil, fmt.Errorf("startup corpus line %d: unknown package manager %q", index+1, manager)
			}
		case "P":
			fields := strings.Fields(rest)
			if len(fields) != 14 {
				return nil, fmt.Errorf("startup corpus line %d: P needs 14 fields, got %d", index+1, len(fields))
			}
			path, err := decodeField(fields[0])
			if err != nil {
				return nil, fmt.Errorf("startup corpus line %d: %w", index+1, err)
			}
			real, err := decodeField(fields[6])
			if err != nil {
				return nil, fmt.Errorf("startup corpus line %d: %w", index+1, err)
			}
			mode, err := strconv.ParseUint(fields[2], 8, 32)
			if err != nil {
				return nil, fmt.Errorf("startup corpus line %d: mode %q: %w", index+1, fields[2], err)
			}
			attrs[path] = trust.Attrs{
				Kind:               kindFromWire(fields[1]),
				Mode:               trust.Mode(uint32(mode)),
				UID:                parseInt(fields[3], -1),
				GID:                parseInt(fields[4], -1),
				Link:               fields[5] == "1",
				Real:               real,
				ParentWritable:     fields[7] == "1",
				ParentOpen:         fields[8] == "1",
				PathParentWritable: fields[9] == "1",
				PathParentOpen:     fields[10] == "1",
				CTime:              parseInt64(fields[11]),
				Inode:              parseUint64(fields[12]),
				Caps:               fields[13] == "1",
			}
		default:
			return nil, fmt.Errorf("startup corpus line %d: unknown tag %q", index+1, tag)
		}
	}

	corpus.facts = func(path string) trust.Facts {
		read, ok := attrs[path]
		if !ok {
			return trust.Build(path, trust.Attrs{Kind: trust.Missing, UID: -1, GID: -1})
		}
		read.Package, read.PackageKnown = packages[path]
		if !read.PackageKnown {
			read.Package, read.PackageKnown = packages[read.Real]
		}
		if !read.PackageKnown {
			read.PackageKnown = dpkgAnswered || rpmAnswered
		}
		return trust.Build(path, read)
	}
	return corpus, nil
}

func decodeField(value string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return "", fmt.Errorf("field %q: %w", value, err)
	}
	return string(decoded), nil
}

func parseInt64(value string) int64 {
	number, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0
	}
	return number
}

func parseUint64(value string) uint64 {
	number, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0
	}
	return number
}

func kindFromWire(value string) trust.Kind {
	switch value {
	case "f":
		return trust.File
	case "d":
		return trust.Dir
	case "o":
		return trust.Other
	}
	return trust.Missing
}

// classifyPath is the one statement of a collected path's surface and dialect.
// The native collector fills File with it after reading, and the sh parser
// rebuilds the same fields from the wire, so a path in a collector list needs
// no second declaration.
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

// isNonUnitPath names every surface a systemd unit name would be wrong for.
func isNonUnitPath(path string) bool {
	return isProfilePath(path) || isCronPath(path) || isInitPath(path) ||
		isLoaderPath(path) || isUdevPath(path) || isSSHPath(path) ||
		isPAMPath(path) || isSupervisorPath(path) || isXdgPath(path) ||
		isAptPath(path) || isModulePath(path)
}

// unitName names the unit a collected systemd file belongs to. A unit file is
// its own name; a drop-in is the directory it sits in, with .d cut.
func unitName(path string) string {
	if isNonUnitPath(path) {
		return ""
	}
	dir := filepath.Dir(path)
	if strings.HasSuffix(dir, ".d") {
		return strings.TrimSuffix(filepath.Base(dir), ".d")
	}
	switch filepath.Ext(path) {
	case ".service", ".socket", ".timer", ".path":
		return filepath.Base(path)
	}
	return ""
}

func isDropIn(path string) bool {
	if isNonUnitPath(path) {
		return false
	}
	return strings.HasSuffix(filepath.Dir(path), ".d")
}

// parseDpkgRows reads `package: path` and `package:arch: path` rows into the
// path → package map. The path is what follows the last separator, which keeps
// a directory name with a colon in it intact.
func parseDpkgRows(out string, packages map[string]string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		cut := strings.LastIndex(line, ": ")
		if cut < 0 {
			continue
		}
		name := line[:cut]
		path := line[cut+2:]
		if at := strings.IndexByte(name, ':'); at >= 0 {
			name = name[:at]
		}
		if name == "" || path == "" {
			continue
		}
		if _, seen := packages[path]; !seen {
			packages[path] = name
		}
	}
}

// parseRPMRows reads `name path` rows from rpm's %{NAME} %{FILENAMES} query.
func parseRPMRows(out string, packages map[string]string) {
	for _, line := range strings.Split(out, "\n") {
		name, path, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || name == "" || path == "" {
			continue
		}
		if _, seen := packages[path]; !seen {
			packages[path] = name
		}
	}
}
