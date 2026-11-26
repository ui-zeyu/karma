//go:build linux

package watch

import (
	"fmt"
	"time"
)

// defaultInterval is the poll cadence when the command did not choose one. A
// process can live shorter than a socket's TIME-WAIT, so the process scan runs
// faster.
func defaultInterval(family Family) time.Duration {
	if family == FamilySocket {
		return 100 * time.Millisecond
	}
	// The connector is the default process source; the poll is the fallback
	// for a container. Fifty milliseconds keeps a burst affordable while a
	// process that lives shorter than a poll is still caught by the connector
	// where the kernel offers it.
	return 50 * time.Millisecond
}

// Open selects a source. The process view prefers the kernel's proc connector
// and falls back to the /proc poll when the kernel or the container refuses the
// subscription. The socket view's auto is the sock_diag poll: it is the source
// that can name the owning process, which is the reason to watch sockets;
// conntrack's flow events carry no owner and stay behind --source conntrack.
func Open(family Family, opt Options) (Source, error) {
	switch opt.Backend {
	case "", "auto":
		if family == FamilyProcess {
			if source, err := newConnector(opt); err == nil {
				return sourceFits(family, source)
			}
		}
		return openPoll(family, opt)
	case "poll":
		return openPoll(family, opt)
	case "connector":
		if family != FamilyProcess {
			return nil, fmt.Errorf("the connector source watches processes only")
		}
		source, err := newConnector(opt)
		if err != nil {
			return nil, connectorUnavailable(err)
		}
		return sourceFits(family, source)
	case "conntrack":
		if family != FamilySocket {
			return nil, fmt.Errorf("the conntrack source watches sockets only")
		}
		source, err := newConntrack(opt)
		if err != nil {
			return nil, conntrackUnavailable(err)
		}
		return sourceFits(family, source)
	case "perf", "ebpf":
		return nil, fmt.Errorf("watch source %q is not available yet; use --source auto", opt.Backend)
	default:
		return nil, fmt.Errorf("unknown watch source %q; use auto|poll|connector|conntrack", opt.Backend)
	}
}

func sourceFits(family Family, source Source) (Source, error) {
	caps := source.Caps()
	if family == FamilyProcess && !caps.Process {
		return nil, fmt.Errorf("source %s does not produce process events", source.Name())
	}
	if family == FamilySocket && !caps.Socket {
		return nil, fmt.Errorf("source %s does not produce socket events", source.Name())
	}
	return source, nil
}

func openPoll(family Family, opt Options) (Source, error) {
	if opt.Interval <= 0 {
		opt.Interval = defaultInterval(family)
	}
	if family == FamilySocket {
		return &socketPoll{interval: opt.Interval, all: opt.All}, nil
	}
	return &procPoll{interval: opt.Interval, all: opt.All}, nil
}
