package startup

import (
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"karma/internal/trust"
)

// The system's own loaders: the objects the init, PAM, NSS, the internet
// superservers and TCP wrappers run by position rather than by a unit file.
// Each of them is an activation edge like any other; nothing here is judged
// by its name.

// generatorDirs are the systemd generator layers. A generator runs before the
// units are loaded, so it can synthesize the units themselves.
var generatorDirs = []string{
	"/etc/systemd/system-generators",
	"/run/systemd/system-generators",
	"/usr/local/lib/systemd/system-generators",
	"/usr/lib/systemd/system-generators",
	"/lib/systemd/system-generators",
}

// userGeneratorDirs are the user-manager generators; they run in a login
// session's own manager.
var userGeneratorDirs = []string{
	"/etc/systemd/user-generators",
	"/run/systemd/user-generators",
	"/usr/local/lib/systemd/user-generators",
	"/usr/lib/systemd/user-generators",
}

// motdDir is the login banner's run-parts directory; pam_motd executes every
// executable in it when a session opens.
var motdDir = "/etc/update-motd.d"

// systemFiles are the boot and name-resolution configuration the kernel and
// libc read by position: mount tables, the name-service switch and the TCP
// wrappers tables.
var systemFiles = []string{
	"/etc/fstab",
	"/etc/crypttab",
	"/etc/nsswitch.conf",
	"/etc/hosts.allow",
	"/etc/hosts.deny",
}

// collectGenerators reads a generator layer: every executable in it. The call
// is gated on systemd being the running init — a container that boots
// supervisord carries the image's generators but never acts on them. A gate
// the collector cannot answer is a coverage line, never a silent skip.
func collectGenerators(fsys FS, corpus *Corpus, dirs []string) {
	if !systemdIsInit(fsys, corpus) {
		return
	}
	for _, dir := range dirs {
		entries, err := fsys.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if info, err := entry.Info(); err == nil && info.Mode().Perm()&0o111 == 0 {
				continue
			}
			addBody(fsys, corpus, File{Path: filepath.Join(dir, entry.Name())})
		}
	}
}

// collectMotd reads the login banner's run-parts directory: every executable
// script in it.
func collectMotd(fsys FS, corpus *Corpus) {
	entries, err := fsys.ReadDir(motdDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if info, err := entry.Info(); err == nil && info.Mode().Perm()&0o111 == 0 {
			continue
		}
		addBody(fsys, corpus, File{Path: filepath.Join(motdDir, entry.Name())})
	}
}

// generatorEdges states a generator as an edge it runs itself: the init
// executes the file by position, so the file is both ends of the relation.
func generatorEdges(file File) []rawEdge {
	return []rawEdge{selfEdge(file, "generator", BootEnabled, Subject{Class: AccountRoot}, Exec)}
}

// motdEdges states the run-parts script itself, then whatever the script
// sources or executes.
func motdEdges(file File) []rawEdge {
	base := rawEdge{
		surface: SurfacePAM, phase: Login, subject: Subject{Class: AccountRoot},
		trigger: file.Path,
	}
	return append([]rawEdge{selfEdge(file, "update-motd", Login, base.subject, Exec)},
		shellEdges(file.Body, base)...)
}

// pamEdges reads a PAM service stack: every module on the stack is mapped
// into the authenticated process, and pam_exec.so runs a program of its own.
// A stack line has one module; its remaining words are the module's own
// arguments, so a later `.so` token is an argument (pam_exec's payload), and
// scanning past the module would mint phantom module rows from it.
func pamEdges(file File, corpus *Corpus) []rawEdge {
	var edges []rawEdge
	for index, raw := range strings.Split(file.Body, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		at := -1
		for position, field := range fields {
			module := strings.TrimPrefix(field, "-")
			if strings.HasSuffix(module, ".so") && !strings.Contains(module, "=") {
				at = position
				break
			}
		}
		if at < 0 {
			continue
		}
		module := strings.TrimPrefix(fields[at], "-")
		args := fields[at+1:]
		if filepath.Base(module) == "pam_exec.so" {
			// The payload is the whole remaining command: a wrapper, a shell
			// holding `-c 'code'`, or a literal program path.
			if target := commandTargetFor(args); !target.dynamic && target.target != "" {
				edges = append(edges, rawEdge{
					surface: SurfacePAM, phase: Login, subject: Subject{Class: AccountRoot},
					trigger: file.Path, line: index + 1, mechanism: "pam_exec",
					target: target.target, kind: target.kind,
					viaInterpreter: target.viaInterpreter,
				})
			}
			continue
		}
		path := findLibrary(module, corpus)
		if path == "" {
			corpus.addGap("PAM module not found: " + module)
			continue
		}
		edges = append(edges, rawEdge{
			surface: SurfacePAM, phase: Login, subject: Subject{Class: AccountRoot},
			trigger: file.Path, line: index + 1, mechanism: "pam",
			target: path, kind: Library,
		})
	}
	return edges
}

// nssEdges reads the name-service switch: every service it names is a library
// libc maps into each process that resolves a name.
func nssEdges(file File, corpus *Corpus) []rawEdge {
	var edges []rawEdge
	for index, line := range strings.Split(file.Body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		for _, field := range strings.Fields(value) {
			if field == "" || strings.HasPrefix(field, "[") {
				continue
			}
			module := "libnss_" + field + ".so.2"
			path := findLibrary(module, corpus)
			if path == "" {
				corpus.addGap("NSS module not found: " + module)
				continue
			}
			edges = append(edges, rawEdge{
				surface: SurfaceSystem, phase: Login, subject: Subject{Class: AccountRoot},
				trigger: file.Path, line: index + 1, mechanism: "nss", target: path, kind: Library,
			})
		}
	}
	return edges
}

// systemEdges states the boot and name-resolution configuration: each file is
// read by position, and the name-service switch and the wrappers tables name
// objects of their own.
func systemEdges(file File, corpus *Corpus) []rawEdge {
	subject := Subject{Class: AccountRoot}
	mechanism := Mechanism(strings.TrimSuffix(strings.TrimPrefix(file.Path, "/etc/"), ".conf"))
	var edges []rawEdge
	switch filepath.Base(file.Path) {
	case "nsswitch.conf":
		edges = append(edges, selfEdge(file, mechanism, Login, subject, Config))
		edges = append(edges, nssEdges(file, corpus)...)
	case "hosts.allow", "hosts.deny":
		edges = append(edges, selfEdge(file, mechanism, BootEnabled, subject, Config))
		edges = append(edges, wrapperCommands(file)...)
	default:
		// fstab and crypttab: mount configuration the boot acts on. The file
		// is one edge of its own, and each row is another — the mount point
		// is what the boot fills with code, and the row's own fields are the
		// note the judge reads.
		edges = append(edges, selfEdge(file, mechanism, BootEnabled, subject, Config))
		switch filepath.Base(file.Path) {
		case "fstab":
			edges = append(edges, fstabEdges(file)...)
		case "crypttab":
			edges = append(edges, crypttabEdges(file)...)
		}
	}
	return edges
}

// fstabEdges states each mount row with an absolute mount point. The row's
// filesystem type and options are the note; a swap row (a `none` mount
// point) names no code-bearing path and stays out.
func fstabEdges(file File) []rawEdge {
	var edges []rawEdge
	for index, raw := range strings.Split(file.Body, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 || !filepath.IsAbs(fields[1]) {
			continue
		}
		edges = append(edges, rawEdge{
			surface: SurfaceSystem, phase: BootEnabled, subject: Subject{Class: AccountRoot},
			trigger: file.Path, line: index + 1, mechanism: "fstab",
			target: fields[1], kind: Config,
			note: strings.Join(fields[2:], " "),
		})
	}
	return edges
}

// crypttabEdges states each encrypted-device row: the mapper device the boot
// assembles is the target, and the row's device, key file and options are the
// note — the key file is what the boot reads to unlock the volume.
func crypttabEdges(file File) []rawEdge {
	var edges []rawEdge
	for index, raw := range strings.Split(file.Body, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		edges = append(edges, rawEdge{
			surface: SurfaceSystem, phase: BootEnabled, subject: Subject{Class: AccountRoot},
			trigger: file.Path, line: index + 1, mechanism: "crypttab",
			target: "/dev/mapper/" + fields[0], kind: Config,
			note: strings.Join(fields[1:], " "),
		})
		if len(fields) >= 3 && filepath.IsAbs(fields[2]) {
			edges = append(edges, rawEdge{
				surface: SurfaceSystem, phase: BootEnabled, subject: Subject{Class: AccountRoot},
				trigger: file.Path, line: index + 1, mechanism: "crypttab-key",
				target: fields[2], kind: Config,
			})
		}
	}
	return edges
}

// wrapperCommands reads the spawn and twist options of a TCP wrappers table:
// each one runs a command of its own when a connection is answered. The
// grammar is daemon:client:options — an option is one colon-separated field
// whose head word is the keyword, and its command runs to the end of the
// line, so a daemon named in.tftspawnd never matches.
func wrapperCommands(file File) []rawEdge {
	base := rawEdge{
		surface: SurfaceSystem, phase: Login, subject: Subject{Class: AccountRoot},
		trigger: file.Path,
	}
	var edges []rawEdge
	for index, line := range strings.Split(file.Body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		for at, field := range fields {
			keyword, head, ok := cutWrapperOption(strings.TrimSpace(field))
			if !ok {
				continue
			}
			rest := strings.TrimSpace(head)
			if at+1 < len(fields) {
				rest = strings.TrimSpace(head + ":" + strings.Join(fields[at+1:], ":"))
			}
			if rest == "" {
				continue
			}
			edges = append(edges, shellEdges(rest, rawEdge{
				surface: base.surface, phase: base.phase, subject: base.subject,
				trigger: base.trigger, line: index + 1, mechanism: Mechanism(keyword),
			})...)
			break
		}
	}
	return edges
}

// cutWrapperOption splits one option field into its keyword and the command
// text that follows it: `spawn /usr/bin/logger hit` or a bare `spawn`.
func cutWrapperOption(field string) (keyword, rest string, ok bool) {
	for _, word := range []string{"spawn", "twist"} {
		if field == word {
			return word, "", true
		}
		if rest, ok = strings.CutPrefix(field, word+" "); ok {
			return word, rest, true
		}
	}
	return "", "", false
}

// xinetdEdges reads an internet superserver definition: `server =` names the
// program a connection runs.
func xinetdEdges(file File) []rawEdge {
	var edges []rawEdge
	for _, d := range parseUnit(file.Body) {
		if d.key != "server" || d.value == "" {
			continue
		}
		value := unquote(d.value)
		if value == "" {
			continue
		}
		edges = append(edges, rawEdge{
			surface: SurfaceSupervisor, phase: Login, subject: Subject{Class: AccountRoot},
			trigger: file.Path, line: d.line, mechanism: "server",
			target: value, kind: Exec, dynamic: !filepath.IsAbs(value),
		})
	}
	return edges
}

// selfEdge states an object the system runs by position: the file is the
// trigger and the target of one relation.
func selfEdge(file File, mechanism Mechanism, phase Phase, subject Subject, kind Kind) rawEdge {
	return rawEdge{
		surface: file.Surface, phase: phase, subject: subject,
		trigger: file.Path, mechanism: mechanism, target: file.Path, kind: kind,
	}
}

// libraryPatterns are the loader's own search locations for a PAM or NSS
// module name, in the order the directories are searched.
func libraryPatterns(name string) []string {
	return []string{
		"/lib/security/" + name, "/usr/lib/security/" + name,
		"/lib/*/security/" + name, "/usr/lib/*/security/" + name,
		"/lib64/security/" + name, "/usr/lib64/security/" + name,
		"/lib/" + name, "/usr/lib/" + name,
		"/lib64/" + name, "/usr/lib64/" + name,
		"/lib/*/" + name, "/usr/lib/*/" + name,
	}
}

// nativeLibDirs are the running image's own multiarch directories, searched
// before the wildcard globs. On a system that carries a foreign architecture
// too, the wildcard's alphabetical first match would point the edge at the
// wrong arch's copy of the module.
func nativeLibDirs() []string {
	triplet := map[string]string{
		"amd64":    "x86_64-linux-gnu",
		"arm64":    "aarch64-linux-gnu",
		"386":      "i386-linux-gnu",
		"arm":      "arm-linux-gnueabihf",
		"loong64":  "loongarch64-linux-gnu",
		"mips64le": "mips64el-linux-gnuabi64",
		"ppc64le":  "powerpc64le-linux-gnu",
		"riscv64":  "riscv64-linux-gnu",
		"s390x":    "s390x-linux-gnu",
	}[runtime.GOARCH]
	if triplet == "" {
		return nil
	}
	return []string{
		"/usr/lib/" + triplet + "/security/",
		"/usr/lib/" + triplet + "/",
		"/lib/" + triplet + "/",
	}
}

// findLibrary resolves a PAM or NSS module name through the loader's own
// directories, through the collector's filesystem. A module the stack names
// but the disk cannot resolve is a coverage gap, not a guess.
func findLibrary(name string, corpus *Corpus) string {
	if filepath.IsAbs(name) {
		if corpus.facts(name).Kind == trust.File {
			return name
		}
		return ""
	}
	patterns := libraryPatterns(name)
	native := nativeLibDirs()
	if len(native) > 0 {
		head := make([]string, len(native))
		for index, dir := range native {
			head[index] = dir + name
		}
		patterns = append(head, patterns...)
	}
	for _, pattern := range patterns {
		matches, err := corpus.fs.Glob(pattern)
		if err != nil {
			continue
		}
		sort.Strings(matches)
		for _, match := range matches {
			if corpus.facts(match).Kind == trust.File {
				return match
			}
		}
	}
	return ""
}

// systemdIsInit reports whether systemd is the running init: only then do the
// vendor enablement links and the generators describe a boot this host acts
// on. /run/systemd/system is the runtime unit dir and can be empty on a
// healthy systemd host, so the answer is the init itself. Both non-answers
// are stated: a comm the collector cannot read is a coverage gap, and an init
// that is not systemd is a stated skip — a silent no is how the old gate
// quietly disabled vendor enablement on a healthy host.
func systemdIsInit(fsys FS, corpus *Corpus) bool {
	comm, err := fsys.ReadFile("/proc/1/comm")
	if err != nil {
		corpus.addGap("systemd init check failed (" + err.Error() + "); generators and vendor enablement skipped")
		return false
	}
	init := strings.TrimSpace(string(comm))
	if init == "systemd" {
		return true
	}
	corpus.addGap("pid 1 is " + init + "; systemd generators and vendor enablement skipped")
	return false
}
