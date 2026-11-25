package audit

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"karma/internal/startup"
	"karma/internal/trust"
)

func parseActivation(text string) (*Snapshot, error) {
	corpus, err := startup.ParseCorpus(text)
	if err != nil {
		return nil, err
	}
	snapshot := &Snapshot{
		Activations: startup.Analyze(corpus),
		Objects:     map[string]trust.Facts{},
		Unreadable:  corpus.Unreadable(),
	}
	for _, edge := range snapshot.Activations {
		remember(snapshot, edge.Trigger, edge.TriggerFacts)
		remember(snapshot, edge.Target, edge.TargetFacts)
	}
	return snapshot, nil
}

// parseAudit rebuilds the snapshot from the sh collector's records. The `name`
// records (O, Y, E, C, L, F, X, H) carry a payload on their next line.
func parseAudit(text string, snapshot *Snapshot) error {
	lines := strings.Split(text, "\n")
	attrs := map[string]trust.Attrs{}
	packages := map[string]string{}
	dpkgAnswered, rpmAnswered := false, false
	authority := map[string]bool{}
	timeline := map[string]time.Time{}
	expected := map[string]ledgerEntry{}
	conffiles := map[string]bool{}
	var ledgerRows []ledgerFile
	var mounts []Mount
	actualHashes := map[string]string{}
	rpmFlags := map[string]string{}
	missing := 0
	note := ""

	for index := 0; index < len(lines); index++ {
		line := strings.TrimSuffix(lines[index], "\r")
		if index == 0 {
			if line != "KARMA-AUDIT 2" {
				return fmt.Errorf("audit corpus: header %q is not %q", line, "KARMA-AUDIT 2")
			}
			continue
		}
		if line == "" {
			continue
		}
		tag, rest, _ := strings.Cut(line, " ")
		switch tag {
		case "T":
			fields := strings.Fields(rest)
			if len(fields) != 6 {
				return fmt.Errorf("audit corpus line %d: T needs 6 fields", index+1)
			}
			container := fields[2] == "1"
			hostname, err := decode(fields[3])
			if err != nil {
				return err
			}
			kernel, err := decode(fields[4])
			if err != nil {
				return err
			}
			osname, err := decode(fields[5])
			if err != nil {
				return err
			}
			kind := "host"
			if container {
				kind = "container"
			}
			snapshot.Host = Host{Hostname: hostname, Kernel: kernel, OS: osname}
			snapshot.Boundary.Kind = kind
		case "K":
			seconds, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
			if err != nil {
				return fmt.Errorf("audit corpus line %d: K %q: %w", index+1, rest, err)
			}
			if seconds > 0 {
				source := "boot"
				if snapshot.Boundary.Kind == "container" {
					source = "pid1"
				}
				snapshot.Boundary.Time = time.Unix(seconds, 0)
				snapshot.Boundary.Source = source
				snapshot.Boundary.Confidence = HighConfidence
			}
		case "P":
			fields := strings.Fields(rest)
			if len(fields) != 14 {
				return fmt.Errorf("audit corpus line %d: P needs 14 fields, got %d", index+1, len(fields))
			}
			path, err := decode(fields[0])
			if err != nil {
				return err
			}
			real, err := decode(fields[6])
			if err != nil {
				return err
			}
			mode, err := strconv.ParseUint(fields[2], 8, 32)
			if err != nil {
				return fmt.Errorf("audit corpus line %d: mode %q: %w", index+1, fields[2], err)
			}
			attrs[path] = trust.Attrs{
				Kind:               kindOf(fields[1]),
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
		case "S":
			line, err := decode(strings.TrimSpace(rest))
			if err != nil {
				return err
			}
			if socket, ok := parseSocketLine(line); ok {
				snapshot.Sockets = append(snapshot.Sockets, socket)
			}
		case "W":
			note, err := decode(strings.TrimSpace(rest))
			if err != nil {
				return err
			}
			snapshot.Coverage = append(snapshot.Coverage, note)
		case "U":
			uid, err := strconv.Atoi(strings.TrimSpace(rest))
			if err != nil {
				return fmt.Errorf("audit corpus line %d: U %q: %w", index+1, rest, err)
			}
			snapshot.Host.UID = uid
		case "V":
			fields := strings.Fields(rest)
			if len(fields) != 5 {
				return fmt.Errorf("audit corpus line %d: V needs 5 fields, got %d", index+1, len(fields))
			}
			unit, err := decode(fields[0])
			if err != nil {
				return err
			}
			load, err := decode(fields[1])
			if err != nil {
				return err
			}
			active, err := decode(fields[2])
			if err != nil {
				return err
			}
			sub, err := decode(fields[3])
			if err != nil {
				return err
			}
			description, err := decode(fields[4])
			if err != nil {
				return err
			}
			snapshot.Services = append(snapshot.Services, Service{
				Unit: unit, Load: load, Active: active, Sub: sub, Description: description,
			})
		case "Q":
			fields := strings.Fields(rest)
			if len(fields) != 11 {
				return fmt.Errorf("audit corpus line %d: Q needs 11 fields, got %d", index+1, len(fields))
			}
			process, err := parseProcess(fields)
			if err != nil {
				return fmt.Errorf("audit corpus line %d: %w", index+1, err)
			}
			snapshot.Processes = append(snapshot.Processes, process)
		case "A":
			path, err := decode(strings.TrimSpace(rest))
			if err != nil {
				return err
			}
			authority[path] = true
		case "D":
			dpkgAnswered = rest == "1"
		case "R":
			rpmAnswered = rest == "1"
		case "O":
			manager, body, err := readBlob(lines, &index, rest)
			if err != nil {
				return err
			}
			switch manager {
			case "dpkg":
				parseDpkgRows(string(body), packages)
			case "rpm":
				parseRPMRows(string(body), packages)
			default:
				return fmt.Errorf("audit corpus line %d: unknown package manager %q", index+1, manager)
			}
		case "Y":
			_, body, err := readBlob(lines, &index, rest)
			if err != nil {
				return err
			}
			for pkg, stamp := range parseTimelineRows(string(body)) {
				if stamp.After(timeline[pkg]) {
					timeline[pkg] = stamp
				}
			}
		case "E":
			_, body, err := readBlob(lines, &index, rest)
			if err != nil {
				return err
			}
			for _, line := range strings.Split(string(body), "\n") {
				pkg, hash, path, ok := parseExpectedRow(line)
				if ok {
					expected[path] = ledgerEntry{pkg: pkg, hash: hash}
				}
			}
		case "C":
			_, body, err := readBlob(lines, &index, rest)
			if err != nil {
				return err
			}
			for _, line := range strings.Split(string(body), "\n") {
				if path, ok := parseConffilesRow(line); ok {
					conffiles[path] = true
				}
			}
		case "L":
			_, body, err := readBlob(lines, &index, rest)
			if err != nil {
				return err
			}
			for _, line := range strings.Split(string(body), "\n") {
				if row, ok := parseLedgerRow(line); ok {
					ledgerRows = append(ledgerRows, row)
				}
			}
		case "F":
			_, body, err := readBlob(lines, &index, rest)
			if err != nil {
				return err
			}
			for _, line := range strings.Split(string(body), "\n") {
				if mount, ok := parseMountsLine(line); ok {
					mounts = append(mounts, mount)
				}
			}
		case "X":
			_, body, err := readBlob(lines, &index, rest)
			if err != nil {
				return err
			}
			for _, line := range strings.Split(string(body), "\n") {
				path, flags, conffile, absent, ok := parseRpmVerifyLine(line)
				if !ok {
					continue
				}
				if absent {
					missing++
					continue
				}
				if conffile {
					conffiles[path] = true
					continue
				}
				if strings.ContainsAny(flags, "SM5") {
					rpmFlags[path] = flags
				}
			}
		case "H":
			_, body, err := readBlob(lines, &index, rest)
			if err != nil {
				return err
			}
			for _, line := range strings.Split(string(body), "\n") {
				hash, path, ok := parseHashRow(line)
				if ok {
					actualHashes[path] = hash
				}
			}
		default:
			return fmt.Errorf("audit corpus line %d: unknown tag %q", index+1, tag)
		}
	}
	if missing > 0 {
		note = fmt.Sprintf("%d packaged file(s) are missing from disk (rpm -Va)", missing)
	}

	previous := snapshot.Objects
	snapshot.Objects = map[string]trust.Facts{}
	build := func(path string) trust.Facts {
		read, ok := attrs[path]
		if !ok {
			if facts, known := previous[path]; known {
				snapshot.Objects[path] = facts
				return facts
			}
			read = trust.Attrs{Kind: trust.Missing, UID: -1, GID: -1, Real: path}
		}
		if read.Real == "" {
			read.Real = path
		}
		read.Package, read.PackageKnown = packages[path]
		if !read.PackageKnown {
			read.Package, read.PackageKnown = packages[read.Real]
		}
		if !read.PackageKnown {
			read.PackageKnown = dpkgAnswered || rpmAnswered
		}
		facts := trust.Build(path, read)
		snapshot.Objects[path] = facts
		return facts
	}
	for path := range attrs {
		build(path)
	}
	for index := range snapshot.Activations {
		edge := &snapshot.Activations[index]
		build(edge.Trigger)
		build(edge.Target)
		edge.TriggerFacts = snapshot.Objects[edge.Trigger]
		edge.TargetFacts = snapshot.Objects[edge.Target]
	}
	for index := range snapshot.Processes {
		process := &snapshot.Processes[index]
		process.ExeFacts = build(process.Exe)
		process.Script, process.ScriptFacts = resolveScript(*process, snapshot.Objects)
	}
	for path := range authority {
		snapshot.Authority = append(snapshot.Authority, path)
		build(path)
	}
	// The path→package answer doubles as the owner index the orphan story
	// reads: it covers the ancestor directories the collector asked about.
	snapshot.ownerOf = make(map[string]string, len(packages))
	for path, pkg := range packages {
		snapshot.ownerOf[path] = pkg
	}
	// Established connections with a resolved owner count per process.
	outbound := map[int]int{}
	for _, socket := range snapshot.Sockets {
		if socket.State == "ESTAB" && socket.PID > 0 {
			outbound[socket.PID]++
		}
	}
	for index := range snapshot.Processes {
		snapshot.Processes[index].Outbound = outbound[snapshot.Processes[index].PID]
	}
	kind := "none"
	switch {
	case dpkgAnswered:
		kind = "dpkg"
	case rpmAnswered:
		kind = "rpm"
	}
	snapshot.attachEvidence(evidenceSet{
		times:     timeline,
		actual:    actualHashes,
		expected:  expected,
		conffiles: conffiles,
		rows:      ledgerRows,
		mounts:    mounts,
		rpmFlag:   rpmFlags,
		kind:      kind,
		note:      note,
	})
	sort.Strings(snapshot.Authority)
	sort.Slice(snapshot.Processes, func(i, j int) bool { return snapshot.Processes[i].PID < snapshot.Processes[j].PID })
	sort.Slice(snapshot.Services, func(i, j int) bool { return snapshot.Services[i].Unit < snapshot.Services[j].Unit })
	sortSockets(snapshot.Sockets)
	if !dpkgAnswered && !rpmAnswered {
		snapshot.Coverage = append(snapshot.Coverage, "package database did not answer; package provenance is unknown")
	}
	return nil
}

// readBlob reads one `name` record: the payload sits on the next line as
// base64 text.
func readBlob(lines []string, index *int, rest string) (string, []byte, error) {
	name := strings.TrimSpace(rest)
	*index++
	if *index >= len(lines) {
		return "", nil, fmt.Errorf("audit corpus line %d: %s is missing its payload", *index, name)
	}
	body, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(lines[*index], "\r"))
	if err != nil {
		return "", nil, fmt.Errorf("audit corpus line %d: %s payload: %w", *index+1, name, err)
	}
	return name, body, nil
}

func parseProcess(fields []string) (Process, error) {
	pid, _ := strconv.Atoi(fields[0])
	ppid, _ := strconv.Atoi(fields[1])
	uid, _ := strconv.Atoi(fields[2])
	gid, _ := strconv.Atoi(fields[3])
	start, _ := strconv.ParseUint(fields[4], 10, 64)
	comm, err := decode(fields[6])
	if err != nil {
		return Process{}, err
	}
	exe, err := decode(fields[7])
	if err != nil {
		return Process{}, err
	}
	cwd, err := decode(fields[8])
	if err != nil {
		return Process{}, err
	}
	root, err := decode(fields[9])
	if err != nil {
		return Process{}, err
	}
	cmdline, err := decode(fields[10])
	if err != nil {
		return Process{}, err
	}
	process := Process{
		PID: pid, PPID: ppid, UID: uid, GID: gid, Start: start,
		State: fields[5], Comm: comm, Cmdline: cmdline, Cwd: cwd, Root: root,
	}
	if strings.HasSuffix(exe, " (deleted)") {
		process.Deleted = true
		exe = strings.TrimSuffix(exe, " (deleted)")
	}
	process.Exe = exe
	return process, nil
}

func resolveScript(process Process, objects map[string]trust.Facts) (string, trust.Facts) {
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
	facts, ok := objects[path]
	if !ok || (!filepath.IsAbs(script) && facts.Kind != trust.File) {
		return "", trust.Facts{}
	}
	return path, facts
}

func decode(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "-" {
		return "", nil
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", fmt.Errorf("field %q: %w", value, err)
	}
	return string(decoded), nil
}

func kindOf(value string) trust.Kind {
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

func parseInt(value string, fallback int) int {
	number, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return number
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
