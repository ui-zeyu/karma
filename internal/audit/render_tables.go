package audit

import (
	"fmt"
	"strconv"
	"strings"

	chrome "karma/internal/panel"
)

func activationRows(view *View, options RenderOptions) []string {
	rows := []string{columnHeader([]string{"SURFACE", "REACH", "AS", "ORIGIN", "TRIGGER"}, []int{10, 12, 10, 10})}
	for _, edge := range view.Activations {
		target := edge.Target
		if edge.Dynamic {
			target = "(dynamic)"
		}
		origin := view.assessor.read(edge.TargetFacts, false).origin
		prefix := columnRowHued(options.Color, []string{
			string(edge.Surface), edge.Phase.String(), valueOr(edge.Subject.String(), "-"), origin.String(),
		}, []int{10, 12, 10, 10}, []int{0, 0, 0, originHue(origin)})
		rows = append(rows, fmt.Sprintf("%s%s:%d", prefix, chrome.SafeText(edge.Trigger), edge.Line))
		rows = append(rows, fmt.Sprintf("    %s -> %s", edge.Mechanism, chrome.SafeText(target)))
	}
	if len(rows) == 1 {
		return nil
	}
	return rows
}

func processRows(view *View, options RenderOptions) []string {
	rows := []string{columnHeader([]string{"PID", "PPID", "UID", "ORIGIN", "REACH", "COMMAND"}, []int{7, 7, 6, 10, 8})}
	for _, process := range view.Processes {
		if process.PID == 0 || process.PID == selfPID() {
			continue
		}
		origin := view.assessor.read(process.ExeFacts, false).origin
		if process.Script != "" {
			origin = weaker(origin, view.assessor.read(process.ScriptFacts, false).origin)
		}
		command := process.Cmdline
		if command == "" {
			command = process.Exe
		}
		if process.Script != "" {
			command = process.Script + " (" + command + ")"
		}
		if process.Outbound > 0 {
			command += fmt.Sprintf("  [%d estab]", process.Outbound)
		}
		prefix := columnRowHued(options.Color, []string{
			strconv.Itoa(process.PID), strconv.Itoa(process.PPID), strconv.Itoa(process.UID),
			origin.String(), processReach(process).String(),
		}, []int{7, 7, 6, 10, 8}, []int{0, 0, 0, originHue(origin), 0})
		rows = append(rows, prefix+chrome.SafeText(valueOr(command, valueOr(process.Exe, process.Comm))))
	}
	if len(rows) == 1 {
		return nil
	}
	return rows
}

func serviceRows(view *View, options RenderOptions) []string {
	rows := []string{columnHeader([]string{"UNIT", "LOAD", "ACTIVE", "SUB", "DESCRIPTION"}, []int{28, 8, 8, 8})}
	for _, service := range view.Services {
		rows = append(rows, columnRowHued(options.Color, []string{
			service.Unit, service.Load, service.Active, service.Sub,
		}, []int{28, 8, 8, 8}, []int{0, 0, serviceStateHue(service.Active), 0})+chrome.SafeText(service.Description))
	}
	if len(rows) == 1 {
		return nil
	}
	return rows
}

func socketRows(view *View, options RenderOptions) []string {
	rows := []string{columnHeader([]string{"PROTO", "STATE", "LOCAL", "PEER", "PID", "COMM"}, []int{6, 9, 24, 24, 7})}
	for _, socket := range view.Sockets {
		rows = append(rows, columnRowHued(options.Color, []string{
			socket.Proto, socket.State, socket.Local, socket.Peer,
			strconv.Itoa(socket.PID), socket.Comm,
		}, []int{6, 9, 24, 24, 7}, []int{0, socketStateHue(socket.State), 0, 0, 0, 0}))
	}
	if len(rows) == 1 {
		return nil
	}
	return rows
}

// connectionRows is the established-connection table: the peer side of the
// listener inventory and the evidence behind an interpreter-socket finding.
// The peer is information in the socket language; a shell's name carries the
// warm hue the interpreter finding states.
func connectionRows(view *View, options RenderOptions) []string {
	if len(view.Connections) == 0 {
		return nil
	}
	processes := make(map[int]Process, len(view.Snapshot.Processes))
	for _, process := range view.Snapshot.Processes {
		processes[process.PID] = process
	}
	rows := []string{columnHeader([]string{"PROTO", "LOCAL", "PEER", "PID", "COMM"}, []int{6, 24, 24, 7, 16})}
	for _, connection := range view.Connections {
		rows = append(rows, columnRowHued(options.Color, []string{
			connection.Proto, connection.Local, connection.Peer,
			strconv.Itoa(connection.PID), connection.Comm,
		}, []int{6, 24, 24, 7, 16},
			[]int{0, 0, hueInformation, 0, connectionHue(connection, processes)}))
	}
	return rows
}

// connectionHue answers the hue of the connection's holder: the warm runtime
// hue when any process holding the socket is a shell or a raw-socket tool.
func connectionHue(connection Connection, processes map[int]Process) int {
	if interpreterHolds(connection.PID, processes) {
		return hueAlert
	}
	for _, pid := range connection.PIDs {
		if interpreterHolds(pid, processes) {
			return hueAlert
		}
	}
	return 0
}

func interpreterHolds(pid int, processes map[int]Process) bool {
	process, ok := processes[pid]
	if !ok {
		return false
	}
	_, interpreter := interpreterClass(process)
	return interpreter
}

// kernelRows is the loaded module inventory: name, use count, state, loader
// flags, the module file's origin, and the file itself. Hidden registries and
// the taint mask follow the table because they are facts about the same state.
func kernelRows(view *View, options RenderOptions) []string {
	state := view.Kernel
	if state == nil || !state.Collected {
		return nil
	}
	rows := []string{columnHeader([]string{"MODULE", "USED", "STATE", "TAINT", "ORIGIN"}, []int{26, 5, 10, 6, 10})}
	scoped := !view.Filter.globalScope()
	for _, module := range state.Modules {
		if scoped && (module.File == "" || !pathOrRealInScope(module.File, module.Facts.Real, view.Filter)) {
			continue
		}
		origin, originCode := "-", 0
		if module.File != "" {
			verdict := view.assessor.read(module.Facts, false)
			origin, originCode = verdict.origin.String(), originHue(verdict.origin)
		}
		file := module.File
		if file == "" && module.FileState != "" {
			file = "(" + module.FileState + ")"
			// An unmapped row says nothing about one module when the whole file
			// database belongs to another kernel.
			if module.FileState == ModuleFileMissing ||
				module.FileState == ModuleFileUnmapped && !state.MappingStale {
				file = paintText(options.Color, fg(hueCaution), file)
			}
		}
		rows = append(rows, columnRowHued(options.Color, []string{
			module.Name, strconv.Itoa(module.Used), valueOr(module.State, "-"), valueOr(module.Taint, "-"), origin,
		}, []int{26, 5, 10, 6, 10},
			[]int{0, 0, moduleStateHue(module.State), taintHue(module.Taint), originCode})+chrome.SafeText(file))
	}
	if !scoped {
		for _, module := range state.Dormant {
			rows = append(rows, paintText(options.Color, fg(mutedColor), "dormant module "+chrome.SafeText(module.Name))+"  "+chrome.SafeText(module.File))
		}
		if state.Tainted != 0 {
			rows = append(rows, paintText(options.Color, fg(hueCaution),
				fmt.Sprintf("taint %d: %s", state.Tainted, strings.Join(state.TaintNames, ", "))))
		}
		for _, hidden := range state.Hidden {
			rows = append(rows, paintText(options.Color, fg(hueAlert),
				"hidden module "+chrome.SafeText(hidden.Name)+" ("+strings.Join(hidden.Views, ", ")+")"))
		}
		for _, pid := range state.HiddenPIDs {
			rows = append(rows, paintText(options.Color, fg(hueAlert), fmt.Sprintf("hidden pid %d", pid)))
		}
	}
	if len(state.LoaderDirs) > 0 {
		rows = append(rows, fmt.Sprintf("loader search path: %d directories", len(state.LoaderDirs)))
	}
	if len(rows) == 1 {
		return nil
	}
	return rows
}

func authorityRows(view *View, options RenderOptions) []string {
	rows := []string{columnHeader([]string{"PATH", "ORIGIN", "REACH", "SETUID", "CAPS"}, []int{44, 10, 8, 7, 5})}
	for _, path := range view.Authority {
		facts := view.Facts(path)
		origin := view.assessor.read(facts, true).origin
		rows = append(rows, columnRowHued(options.Color, []string{
			path, origin.String(), authorityReach(facts).String(),
			strconv.FormatBool(facts.Setuid), strconv.FormatBool(facts.Caps),
		}, []int{44, 10, 8, 7, 5}, []int{0, originHue(origin), 0, 0, 0}))
	}
	if len(rows) == 1 {
		return nil
	}
	return rows
}

// mountRows list the mount table: where evidence lives and which of it dies
// with the boot.
func mountRows(view *View, options RenderOptions) []string {
	if len(view.Mounts) == 0 {
		return nil
	}
	rows := []string{columnHeader([]string{"FSTYPE", "PATH", "OPTS"}, []int{12, 26, 34})}
	for _, mount := range view.Mounts {
		rows = append(rows, columnRowHued(options.Color, []string{mount.FSType, mount.Path, mount.Opts},
			[]int{12, 26, 34}, []int{mountTypeHue(mount.FSType), 0, 0}))
	}
	return rows
}

func severityColor(severity Severity) int {
	switch severity {
	case Critical:
		return 1
	case High:
		return 9
	case Medium:
		return 11
	case Low:
		return 14
	}
	return mutedColor
}

func columnHeader(columns []string, widths []int) string {
	return columnRow(columns, widths)
}

func columnRow(values []string, widths []int) string {
	var out strings.Builder
	for index, value := range values {
		if index >= len(widths) {
			out.WriteString(value)
			break
		}
		width := widths[index]
		value = chrome.SafeText(value)
		out.WriteString(padRight(truncate(value, width), width))
		out.WriteString("  ")
	}
	return out.String()
}

// columnRowHued is columnRow with one hue per cell: the padding is painted
// with the cell, so the columns stay aligned; a zero hue leaves it plain.
func columnRowHued(color bool, values []string, widths []int, hues []int) string {
	var out strings.Builder
	for index, value := range values {
		if index >= len(widths) {
			out.WriteString(value)
			break
		}
		width := widths[index]
		value = chrome.SafeText(value)
		cell := padRight(truncate(value, width), width)
		if index < len(hues) && hues[index] != 0 {
			cell = paintText(color, fg(hues[index]), cell)
		}
		out.WriteString(cell)
		out.WriteString("  ")
	}
	return out.String()
}

// originHue is the row palette's temporal verdict, the same language the
// relation tree marks its nodes with: a runtime object warm red, a modified
// or unknown one amber, provisioned calmer, the artifact's own origins muted.
func originHue(origin Origin) int {
	switch origin {
	case Runtime:
		return hueAlert
	case Modified, Unknown:
		return hueCaution
	case Provisioned:
		return hueProvisioned
	}
	return mutedColor
}

// serviceStateHue: a running service is healthy green, a failed one red, a
// transition amber, an inactive one quiet.
func serviceStateHue(state string) int {
	switch state {
	case "active":
		return hueLive
	case "failed":
		return hueFailed
	case "activating", "deactivating", "reloading":
		return hueTransition
	case "inactive":
		return mutedColor
	}
	return 0
}

// socketStateHue: a listening socket asks for attention (amber), an
// established peer is information (cyan), the rest is quiet.
func socketStateHue(state string) int {
	switch state {
	case "LISTEN":
		return hueTransition
	case "ESTAB", "ESTABLISHED":
		return hueInformation
	}
	return 0
}

// moduleStateHue: a loaded module is live, a load or unload in flight is a
// transition, the rest is quiet.
func moduleStateHue(state string) int {
	switch state {
	case "Live":
		return hueLive
	case "Loading", "Unloading":
		return hueTransition
	}
	return 0
}

// taintHue: a loader flag on one module is a caution; an empty column is
// quiet.
func taintHue(taint string) int {
	if taint == "" || taint == "-" {
		return 0
	}
	return hueCaution
}

// mountTypeHue: a remote filesystem is information (cyan), a memory-backed
// one is amber because its evidence dies with the boot.
func mountTypeHue(fstype string) int {
	switch fstype {
	case "nfs", "nfs4", "cifs", "smb3", "smbfs", "sshfs", "fuse.sshfs", "9p", "afs", "nbd":
		return hueInformation
	case "tmpfs", "ramfs", "devtmpfs":
		return hueTransition
	}
	return 0
}
