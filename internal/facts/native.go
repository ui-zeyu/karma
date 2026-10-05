// The local channel's fact collection: the same facts Collect gathers over a
// session, read in process — capability probe via the same PATH search the
// shell's command -v does, hostname, kernel release, distro name, and uid
// from their kernel interfaces.

package facts

import (
	"os"
	"os/exec"

	"karma/internal/model"
)

// collectLocal gathers the facts where karma itself is the target: no round
// trips, no shell. The shapes match Collect's outputs field for field so the
// report header and the runner's capability gating read either the same way.
func collectLocal(bins []string) model.HostFacts {
	return model.HostFacts{
		AvailableBins: localBins(bins),
		Hostname:      localHostname(),
		Kernel:        localKernel(),
		OsPretty:      prettyName(localOsRelease()),
		UID:           os.Getuid(),
	}
}

// localBins answers the capability probe with the same PATH search command -v
// performs.
func localBins(wanted []string) map[string]bool {
	set := make(map[string]bool, len(wanted))
	for _, name := range wanted {
		_, err := exec.LookPath(name)
		set[name] = err == nil
	}
	return set
}

// localHostname: the kernel's own hostname, with os.Hostname as the fallback.
func localHostname() string {
	if data, err := os.ReadFile("/proc/sys/kernel/hostname"); err == nil {
		if name := firstLine(string(data), ""); name != "" {
			return name
		}
	}
	if name, err := os.Hostname(); err == nil && name != "" {
		return name
	}
	return "unknown"
}

// localOsRelease reads the distro's pretty name source.
func localOsRelease() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	return string(data)
}
