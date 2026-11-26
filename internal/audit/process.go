package audit

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"karma/internal/startup"
	"karma/internal/trust"
)

// processScope narrows the process scan. A unit profile reads the cgroup of
// every pid (cheap) and details only the unit's own processes; a pid profile
// reads that process. The zero scope is the whole host.
type processScope struct {
	unit string
	pids map[int]bool
}

// collectProcesses reads the running principals. The image and the script an
// interpreter carries are judged by origin later; here they are only facts.
// Ownership is prefetched for every image in one batch before the facts are
// read: a host with hundreds of processes must not cost one package-manager
// call per process.
func collectProcesses(ctx context.Context, facts func(string) trust.Facts, prefetch func([]string), scope processScope) ([]Process, []string) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, []string{"running processes could not be read: " + err.Error()}
	}
	processes := make([]Process, 0, len(entries))
	var gaps []string
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return processes, gaps
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if scope.pids != nil && !scope.pids[pid] {
			continue
		}
		if scope.unit != "" {
			unit := readCgroupUnit(pid)
			if unit != scope.unit && templateUnit(unit) != scope.unit {
				continue
			}
		}
		process, ok := readProcess(pid)
		if !ok {
			continue
		}
		processes = append(processes, process)
	}
	// One hop of parent context: a shell or supervisor that launched the
	// selected process is part of its story.
	selected := make(map[int]bool, len(processes))
	for _, process := range processes {
		selected[process.PID] = true
	}
	initial := len(processes)
	for index := 0; index < initial; index++ {
		parent := processes[index].PPID
		if parent <= 1 || selected[parent] {
			continue
		}
		if process, ok := readProcess(parent); ok {
			processes = append(processes, process)
			selected[parent] = true
		}
	}
	paths := make([]string, 0, len(processes)*3)
	for _, process := range processes {
		paths = append(paths, process.Exe, process.Script)
		for _, target := range process.LoaderTargets {
			if filepath.IsAbs(target.Path) {
				paths = append(paths, target.Path)
			}
		}
	}
	if prefetch != nil {
		prefetch(paths)
	}
	for index := range processes {
		processes[index].ExeFacts = facts(processes[index].Exe)
		processes[index].ScriptFacts = facts(processes[index].Script)
		for target := range processes[index].LoaderTargets {
			path := processes[index].LoaderTargets[target].Path
			if filepath.IsAbs(path) {
				processes[index].LoaderTargets[target].Facts = facts(path)
			}
		}
	}
	sort.Slice(processes, func(i, j int) bool { return processes[i].PID < processes[j].PID })
	return processes, gaps
}

// readCgroupUnit answers the systemd unit for a pid without reading the rest
// of its process record.
func readCgroupUnit(pid int) string {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return ""
	}
	return unitFromCgroup(string(data))
}

func readProcess(pid int) (Process, bool) {
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return Process{}, false
	}
	process := Process{PID: pid}
	text := string(stat)
	open := strings.IndexByte(text, '(')
	end := strings.LastIndexByte(text, ')')
	if open < 0 || end < open {
		return Process{}, false
	}
	process.Comm = text[open+1 : end]
	fields := strings.Fields(text[end+2:])
	if len(fields) < 20 {
		return Process{}, false
	}
	process.State = fields[0]
	process.PPID, _ = strconv.Atoi(fields[1])
	process.Start, _ = strconv.ParseUint(fields[19], 10, 64)
	process.UID, process.GID, process.EUID, process.EGID, process.CapEff, process.Seccomp, process.NoNewPrivs = readStatus(pid)

	base := "/proc/" + strconv.Itoa(pid)
	if data, err := os.ReadFile(base + "/environ"); err == nil {
		process.LoaderTargets, process.LibraryPath = loaderEnvironment(string(data))
	}
	if raw, err := os.ReadFile(base + "/cmdline"); err == nil {
		process.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(raw), "\x00", " "))
	}
	if cwd, err := os.Readlink(base + "/cwd"); err == nil {
		process.Cwd = cwd
	}
	if root, err := os.Readlink(base + "/root"); err == nil {
		process.Root = root
	}
	if data, err := os.ReadFile(base + "/cgroup"); err == nil {
		process.Cgroup = strings.TrimSpace(string(data))
		process.Unit = unitFromCgroup(process.Cgroup)
	}
	exe, err := os.Readlink(base + "/exe")
	if err != nil {
		// A process of another account may hide its exe from this one. The
		// command line still names the image, and an interpreter's first
		// argument still names the script, so the judgment reads what is
		// visible instead of dropping the process.
		exe = argv0(process.Cmdline, process.Cwd)
	}
	if strings.HasSuffix(exe, " (deleted)") {
		process.Deleted = true
		exe = strings.TrimSuffix(exe, " (deleted)")
	}
	process.Exe = exe
	process.Script = readScript(process)
	return process, true
}

// argv0 is the command line's first word, resolved to an absolute path when
// the process's own exe link is unreadable. A bare name is looked up in the
// distribution's program directories; a relative path is joined to the cwd.
func argv0(cmdline, cwd string) string {
	fields := strings.Fields(cmdline)
	if len(fields) == 0 {
		return ""
	}
	name := fields[0]
	switch {
	case filepath.IsAbs(name):
		return name
	case strings.ContainsRune(name, '/'):
		if cwd != "" {
			return filepath.Join(cwd, name)
		}
		return ""
	}
	for _, dir := range []string{"/bin", "/usr/bin", "/sbin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"} {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

// unitFromCgroup names the deepest systemd unit a cgroup path holds. cgroup
// v2 is `0::/system.slice/ssh.service`; v1 repeats the path per controller.
// A bare slice is not the process's unit and yields nothing.
func unitFromCgroup(text string) string {
	unit := ""
	for _, line := range strings.Split(text, "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) < 3 {
			continue
		}
		for _, segment := range strings.Split(fields[2], "/") {
			if strings.HasSuffix(segment, ".service") || strings.HasSuffix(segment, ".scope") {
				unit = segment
			}
		}
	}
	return unit
}

// readStatus reads the identity and the kernel-enforced context in one pass:
// uid/gid, the effective capability mask, the seccomp mode and no_new_privs.
func readStatus(pid int) (uid, gid, euid, egid int, caps uint64, seccomp int, noNewPrivs bool) {
	status, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return -1, -1, -1, -1, 0, 0, false
	}
	uid, gid, euid, egid = -1, -1, -1, -1
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "Uid:":
			// real, effective, saved, filesystem
			if len(fields) > 1 {
				uid, _ = strconv.Atoi(fields[1])
			}
			if len(fields) > 2 {
				euid, _ = strconv.Atoi(fields[2])
			}
		case "Gid:":
			if len(fields) > 1 {
				gid, _ = strconv.Atoi(fields[1])
			}
			if len(fields) > 2 {
				egid, _ = strconv.Atoi(fields[2])
			}
		case "CapEff:":
			caps, _ = strconv.ParseUint(fields[1], 16, 64)
		case "Seccomp:":
			seccomp, _ = strconv.Atoi(fields[1])
		case "NoNewPrivs:":
			noNewPrivs = fields[1] != "0"
		}
	}
	return uid, gid, euid, egid, caps, seccomp, noNewPrivs
}

// loaderEnvironment reads the dynamic-loader variables out of a /proc
// environ block. A soname is kept as a target even when it cannot be
// classified; it is still a lead.
func loaderEnvironment(environ string) ([]LoaderTarget, string) {
	targets := []LoaderTarget{}
	libraryPath := ""
	for _, entry := range strings.Split(environ, "\x00") {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || value == "" {
			continue
		}
		switch name {
		case "LD_PRELOAD", "LD_AUDIT":
			for _, path := range strings.FieldsFunc(value, func(r rune) bool {
				return r == ':' || r == ' ' || r == '\t'
			}) {
				if path != "" {
					targets = append(targets, LoaderTarget{Variable: name, Path: path})
				}
			}
		case "LD_LIBRARY_PATH":
			libraryPath = value
		}
	}
	return targets, libraryPath
}

// readScript resolves the file an interpreter carries. A relative argument is
// joined to the process's cwd and is a script only when that path is a file;
// otherwise it is an option value or a module name.
func readScript(process Process) string {
	if process.Exe == "" || !startup.IsInterpreter(process.Exe) {
		return ""
	}
	script := startup.ScriptArg(process.Cmdline)
	if script == "" {
		return ""
	}
	path := script
	if !filepath.IsAbs(path) {
		if process.Cwd == "" {
			return ""
		}
		path = filepath.Join(process.Cwd, path)
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return ""
		}
	}
	return path
}
