package audit

import (
	"context"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// collectServices reads systemd's own service inventory. It is the raw list
// behind the activation edges, and it names a running service whose unit file
// the filesystem collector did not find.
func collectServices(ctx context.Context) ([]Service, []string) {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return nil, nil
	}
	binary, err := exec.LookPath("systemctl")
	if err != nil {
		return nil, []string{"systemd is running but systemctl is not on PATH; the service inventory is missing"}
	}
	bound, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(bound, binary,
		"list-units", "--type=service", "--all", "--no-pager", "--no-legend").Output()
	if len(out) == 0 && err != nil {
		return nil, []string{"systemctl list-units did not answer: " + err.Error()}
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
