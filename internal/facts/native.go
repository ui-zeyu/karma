// The local channel's fact collection: the same facts Collect gathers over a
// session, read in process — hostname, kernel release, distro name, and uid from
// their kernel interfaces. There is no capability probe here: karma itself is the
// target, so whether a tool exists is what the run finds out when it calls it.

package facts

import (
	"os"

	"karma/internal/localfs"
	"karma/internal/model"
)

// collectLocal gathers the facts where karma itself is the target: no round
// trips, no shell. The shapes match Collect's outputs field for field so the
// report header reads either the same way.
func collectLocal() model.HostFacts {
	return model.HostFacts{
		Hostname: localHostname(),
		Kernel:   localKernel(),
		OsPretty: prettyName(localOsRelease()),
		UID:      os.Getuid(),
	}
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
	data, err := localfs.ReadRegular("/etc/os-release")
	if err != nil {
		return ""
	}
	return string(data)
}
