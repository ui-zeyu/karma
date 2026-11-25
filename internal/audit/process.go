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

// collectProcesses reads the running principals. The image and the script an
// interpreter carries are judged by origin later; here they are only facts.
func collectProcesses(ctx context.Context, facts func(string) trust.Facts) ([]Process, []string) {
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
		process, ok := readProcess(pid, facts)
		if !ok {
			continue
		}
		processes = append(processes, process)
	}
	sort.Slice(processes, func(i, j int) bool { return processes[i].PID < processes[j].PID })
	return processes, gaps
}

func readProcess(pid int, facts func(string) trust.Facts) (Process, bool) {
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
	process.UID, process.GID = readIDs(pid)

	base := "/proc/" + strconv.Itoa(pid)
	if raw, err := os.ReadFile(base + "/cmdline"); err == nil {
		process.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(raw), "\x00", " "))
	}
	if cwd, err := os.Readlink(base + "/cwd"); err == nil {
		process.Cwd = cwd
	}
	if root, err := os.Readlink(base + "/root"); err == nil {
		process.Root = root
	}
	exe, err := os.Readlink(base + "/exe")
	if err != nil {
		// A process of another account may hide its exe from this one. The
		// command line still names the image, and an interpreter's first
		// argument still names the script, so the judgment reads what is
		// visible instead of dropping the process.
		exe = argv0(process.Cmdline, process.Cwd)
	}
	process.Exe = exe
	if strings.HasSuffix(exe, " (deleted)") {
		process.Deleted = true
		exe = strings.TrimSuffix(exe, " (deleted)")
	}
	process.ExeFacts = facts(exe)
	process.Script, process.ScriptFacts = readScript(process, facts)
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

func readIDs(pid int) (uid, gid int) {
	status, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return -1, -1
	}
	uid, gid = -1, -1
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "Uid:":
			uid, _ = strconv.Atoi(fields[1])
		case "Gid:":
			gid, _ = strconv.Atoi(fields[1])
		}
	}
	return uid, gid
}

// readScript resolves the file an interpreter carries. A relative argument is
// joined to the process's cwd and is a script only when that path is a file;
// otherwise it is an option value or a module name.
func readScript(process Process, facts func(string) trust.Facts) (string, trust.Facts) {
	if process.Exe == "" || !startup.IsInterpreter(process.Exe) {
		return "", trust.Facts{}
	}
	script := startup.ScriptArg(process.Cmdline)
	if script == "" {
		return "", trust.Facts{}
	}
	path := script
	if !filepath.IsAbs(path) {
		if process.Cwd == "" {
			return "", trust.Facts{}
		}
		path = filepath.Join(process.Cwd, path)
	}
	read := facts(path)
	if !filepath.IsAbs(script) && read.Kind != trust.File {
		return "", trust.Facts{}
	}
	return path, read
}
