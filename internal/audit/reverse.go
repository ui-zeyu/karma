package audit

// A socket is a relationship, not a file attribute. The listener table states
// what a host offers; an established connection states who a process is
// talking to. An interpreter that holds one is the shape of a reverse shell:
// the image is package-owned and old, and only the process-to-peer edge is
// anomalous.

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

var shellInterpreters = map[string]bool{
	"bash": true, "sh": true, "dash": true, "zsh": true, "ksh": true,
	"fish": true, "ash": true, "busybox": true,
}

var socketInterpreters = map[string]bool{
	"nc": true, "ncat": true, "netcat": true, "socat": true,
}

var scriptInterpreters = map[string]bool{
	"python": true, "python2": true, "python3": true,
	"perl": true, "ruby": true, "php": true, "node": true,
}

// interpreterClass reads a process image and answers how much a socket in its
// hand means. A shell or a raw-socket tool is a verdict; a scripting runtime
// is only a verdict when no service unit explains it.
func interpreterClass(process Process) (string, bool) {
	name := strings.ToLower(filepath.Base(process.Exe))
	if name == "" {
		name = strings.ToLower(process.Comm)
	}
	if shellInterpreters[name] || socketInterpreters[name] {
		return name, true
	}
	// An inline runtime with no service unit is the reverse-shell shape. A
	// script file run by cron or a unit has an artifact behind it and is left
	// to the normal process checks.
	if scriptInterpreters[name] && process.Unit == "" && process.Script == "" {
		return name, true
	}
	return "", false
}

// judgeConnections groups the established and listening sockets by process and
// states the interpreter shapes once per process, with the peers in the chain.
func judgeConnections(snapshot *Snapshot, filter Filter, add func(Finding)) {
	processes := make(map[int]Process, len(snapshot.Processes))
	for _, process := range snapshot.Processes {
		processes[process.PID] = process
	}
	type peerSet struct {
		process  Process
		listener []string
		outbound []string
	}
	byPID := map[int]*peerSet{}
	get := func(pid int) *peerSet {
		if entry, ok := byPID[pid]; ok {
			return entry
		}
		process, ok := processes[pid]
		if !ok {
			return nil
		}
		entry := &peerSet{process: process}
		byPID[pid] = entry
		return entry
	}
	for _, socket := range snapshot.Sockets {
		entry := get(socket.PID)
		if entry == nil {
			continue
		}
		entry.listener = append(entry.listener, socket.Local)
	}
	for _, connection := range snapshot.Connections {
		owners := connection.PIDs
		if len(owners) == 0 {
			owners = []int{connection.PID}
		}
		for _, pid := range owners {
			entry := get(pid)
			if entry == nil {
				continue
			}
			entry.outbound = append(entry.outbound, connection.Peer)
		}
	}
	pids := make([]int, 0, len(byPID))
	for pid := range byPID {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	for _, pid := range pids {
		entry := byPID[pid]
		process := entry.process
		if process.PID == selfPID() || !processInScope(process, filter) {
			continue
		}
		name, interesting := interpreterClass(process)
		if !interesting {
			continue
		}
		reach := processReach(process)
		severity := Severity(Medium)
		switch {
		case reach >= RootAsset:
			severity = Critical
		case reach == ServiceAsset:
			severity = High
		}
		if len(entry.outbound) > 0 {
			add(Finding{
				Class: "interpreter-socket", Severity: severity,
				Title: "interpreter holds an established connection",
				Path:  process.Exe, Origin: Unknown, Reach: reach,
				Detail: fmt.Sprintf("%s has %d established connection(s); the shape is a reverse shell",
					name, len(entry.outbound)),
				Evidence: []string{
					fmt.Sprintf("pid %d uid %d %s", process.PID, process.UID, process.Cmdline),
					"peers: " + strings.Join(limitStrings(entry.outbound, 5), ", "),
				},
				Trace: steps("process "+name, "holds socket", "peer "+entry.outbound[0]),
			})
		}
		if len(entry.listener) > 0 {
			add(Finding{
				Class: "interpreter-listener", Severity: severity,
				Title: "interpreter holds a listening socket",
				Path:  process.Exe, Origin: Unknown, Reach: reach,
				Detail: fmt.Sprintf("%s listens on %s; the shape is a bind shell",
					name, strings.Join(limitStrings(entry.listener, 3), ", ")),
				Evidence: []string{
					fmt.Sprintf("pid %d uid %d %s", process.PID, process.UID, process.Cmdline),
				},
				Trace: steps("process "+name, "listens", entry.listener[0]),
			})
		}
	}
}

func containsPID(pids []int, pid int) bool {
	for _, value := range pids {
		if value == pid {
			return true
		}
	}
	return false
}

func limitStrings(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	return append(values[:limit:limit], fmt.Sprintf("and %d more", len(values)-limit))
}
