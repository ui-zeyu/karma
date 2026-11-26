package audit

import (
	"bufio"
	"encoding/binary"
	"os"
	"strconv"
	"strings"
	"time"

	"karma/internal/localfs"
)

// readBoundary answers the artifact's edge and the package transactions that
// can explain a file newer than it. A container's edge is PID 1's start (the
// host's boot time predates the container by however long the host has run);
// a host's edge is its own boot, with package transactions after it marking
// provisioned installs.
func readBoundary(packageTimes map[string]time.Time) (Boundary, map[string]time.Time) {
	boot := readBootTime()
	if isContainer() {
		if start := readPID1Start(boot); !start.IsZero() {
			return Boundary{Time: start, Kind: "container", Source: "pid1", Confidence: HighConfidence}, packageTimes
		}
	}
	// On a long-lived host the boot is not the artifact edge: package updates
	// run for months after it, and a boot boundary would read every one as a
	// runtime modification. The last package transaction is the host's real
	// artifact edge; a host with no later transaction keeps a short boot
	// provisioning window for its generated host keys and machine id.
	last := latestPackageTime(packageTimes)
	if !last.IsZero() && (boot.IsZero() || last.After(boot)) {
		return Boundary{Time: last, Kind: "host", Source: "package", Confidence: HighConfidence}, packageTimes
	}
	if !boot.IsZero() {
		return Boundary{Time: boot.Add(5 * time.Minute), Kind: "host", Source: "boot", Confidence: MediumConfidence}, packageTimes
	}
	if !last.IsZero() {
		return Boundary{Time: last, Kind: "host", Source: "package", Confidence: MediumConfidence}, packageTimes
	}
	return Boundary{Kind: "unknown", Source: "none", Confidence: LowConfidence}, packageTimes
}

func readBootTime() time.Time {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}
	}
	for _, line := range strings.Split(string(data), "\n") {
		seconds, ok := strings.CutPrefix(line, "btime ")
		if !ok {
			continue
		}
		value, err := strconv.ParseInt(strings.TrimSpace(seconds), 10, 64)
		if err != nil {
			return time.Time{}
		}
		return time.Unix(value, 0)
	}
	return time.Time{}
}

// readPID1Start reads the container's birth: PID 1's start time in clock ticks
// after boot. The stat line keeps the command in parentheses, so the fields
// begin after the last ')'.
func readPID1Start(boot time.Time) time.Time {
	if boot.IsZero() {
		return time.Time{}
	}
	data, err := os.ReadFile("/proc/1/stat")
	if err != nil {
		return time.Time{}
	}
	text := string(data)
	end := strings.LastIndexByte(text, ')')
	if end < 0 || end+2 >= len(text) {
		return time.Time{}
	}
	fields := strings.Fields(text[end+2:])
	// state is field 1 after the command; starttime is the 20th.
	if len(fields) < 20 {
		return time.Time{}
	}
	ticks, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil {
		return time.Time{}
	}
	return boot.Add(time.Duration(ticks) * (time.Second / time.Duration(clockTicks())))
}

// clockTicks is the kernel's USER_HZ from the auxiliary vector (AT_CLKTCK).
// Assuming 100 is common but wrong on a kernel configured otherwise; the
// container boundary would then move by tens of seconds.
func clockTicks() int64 {
	const atClkTck = 17
	data, err := os.ReadFile("/proc/self/auxv")
	if err != nil || len(data) < 16 {
		return 100
	}
	for index := 0; index+16 <= len(data); index += 16 {
		kind := binary.NativeEndian.Uint64(data[index:])
		value := binary.NativeEndian.Uint64(data[index+8:])
		if kind == atClkTck && value > 0 {
			return int64(value)
		}
	}
	return 100
}

// isContainer asks the kernel's own views: the marker files, the init cgroup,
// and the root mount's filesystem type.
func isContainer() bool {
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv", "/run/systemd/container"} {
		if _, err := os.Stat(marker); err == nil {
			return true
		}
	}
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		text := string(data)
		for _, word := range []string{"docker", "kubepods", "containerd", "lxc", "podman", "garden"} {
			if strings.Contains(text, word) {
				return true
			}
		}
	}
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 9 || fields[4] != "/" {
			continue
		}
		for index, field := range fields {
			if field == "-" && index+1 < len(fields) {
				switch fields[index+1] {
				case "overlay", "fuse.lxcfs":
					return true
				}
			}
		}
	}
	return false
}

func latestPackageTime(times map[string]time.Time) time.Time {
	var latest time.Time
	for _, stamp := range times {
		if stamp.After(latest) {
			latest = stamp
		}
	}
	return latest
}

func readHost() Host {
	hostname, _ := os.Hostname()
	kernel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	return Host{
		Hostname: hostname,
		Kernel:   strings.TrimSpace(string(kernel)),
		OS:       readOSName(),
		UID:      os.Getuid(),
	}
}

func readOSName() string {
	data, err := localfs.ReadFile("/etc/os-release", 64<<10)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if name, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			return strings.Trim(name, `"`)
		}
	}
	return ""
}
