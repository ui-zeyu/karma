package audit

import (
	"context"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

func systemctlBinary() string {
	for _, path := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return path
		}
	}
	return ""
}

func toolEnv() []string {
	return []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/",
		"TMPDIR=/tmp",
		"LANG=C",
		"LC_ALL=C",
	}
}

// systemctl runs one systemctl query on a bounded budget. Empty output with
// an error is an absent answer; partial output with an error still names what
// systemd said, and the error becomes a stated degradation — the two callers
// no longer disagree about that policy.
func systemctl(ctx context.Context, budget time.Duration, coverage []Coverage, args ...string) ([]byte, []Coverage) {
	binary := systemctlBinary()
	if binary == "" {
		return nil, append(coverage, coverageAbsent("services",
			"systemd is running but systemctl is not in the system directories; the service inventory is missing"))
	}
	bound, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	cmd := exec.CommandContext(bound, binary, args...)
	cmd.Env = toolEnv()
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return nil, append(coverage, coverageAbsent("services", "systemctl "+args[0]+" did not answer: "+err.Error()))
	}
	if err != nil {
		coverage = append(coverage, coverageGap("services", "systemctl "+args[0]+" answered partly: "+err.Error()))
	}
	return out, coverage
}

// collectServiceScoped answers one unit's state with `systemctl show`. A
// graph of one unit does not need the host's whole unit inventory, and
// listing every unit can take seconds on a busy host.
func collectServiceScoped(ctx context.Context, name string) ([]Service, []Coverage) {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return nil, nil
	}
	out, coverage := systemctl(ctx, 3*time.Second, nil, "show", name, "--no-pager",
		"--property=LoadState,ActiveState,SubState,Description")
	if out == nil {
		return nil, coverage
	}
	service := Service{Unit: name}
	for _, line := range strings.Split(string(out), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "LoadState":
			service.Load = value
		case "ActiveState":
			service.Active = value
		case "SubState":
			service.Sub = value
		case "Description":
			service.Description = value
		}
	}
	return []Service{service}, nil
}

// collectServices reads systemd's own service inventory. It is the raw list
// behind the activation edges, and it names a running service whose unit file
// the filesystem collector did not find.
func collectServices(ctx context.Context) ([]Service, []Coverage) {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return nil, nil
	}
	out, coverage := systemctl(ctx, 8*time.Second, nil,
		"list-units", "--type=service", "--all", "--no-pager", "--no-legend")
	if out == nil {
		return nil, coverage
	}
	var services []Service
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "●"))
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		services = append(services, Service{
			Unit: fields[0], Load: fields[1], Active: fields[2], Sub: fields[3],
			Description: strings.Join(fields[4:], " "),
		})
	}
	sort.Slice(services, func(i, j int) bool { return services[i].Unit < services[j].Unit })
	return services, nil
}
