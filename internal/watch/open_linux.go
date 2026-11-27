//go:build linux

package watch

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
)

// DefaultInterval is the poll cadence a command registers as its flag
// default, and the cadence Open falls back to when the caller chose none. A
// process can live shorter than a socket's TIME-WAIT, so the process scan runs
// faster.
func DefaultInterval(family Family) time.Duration {
	if family == FamilySocket {
		return 100 * time.Millisecond
	}
	// The connector is the default process source; the poll is the fallback
	// for a container. Fifty milliseconds keeps a burst affordable while a
	// process that lives shorter than a poll is still caught by the connector
	// where the kernel offers it.
	return 50 * time.Millisecond
}

// familyBits is the one-family mask a backend's families field states.
func familyBits(family Family) uint8 { return 1 << family }

// familyPlural is a family's name in the refusal sentences: the connector
// watches processes, the conntrack source watches sockets.
func familyPlural(family Family) string {
	if family == FamilySocket {
		return "sockets"
	}
	return "processes"
}

// backend is one registered source: the families its events fill, and the
// constructor Open calls. The registry is the one statement of which sources
// exist, what they watch and how they are built — the family guard reads the
// same mask the auto resolution matches against.
type backend struct {
	families uint8
	planned  bool
	new      func(context.Context, Family, Options) (Source, error)
}

// backends is the source registry, keyed by the --source word.
var backends = map[string]backend{
	"poll": {families: familyBits(FamilyProcess) | familyBits(FamilySocket), new: newPoll},
	"connector": {families: familyBits(FamilyProcess), new: func(ctx context.Context, _ Family, opt Options) (Source, error) {
		return newConnector(ctx, opt)
	}},
	"conntrack": {families: familyBits(FamilySocket), new: func(_ context.Context, _ Family, opt Options) (Source, error) {
		return newConntrack(opt)
	}},
	"perf": {planned: true},
	"ebpf": {planned: true},
}

// autoOrder is the preference the auto backend resolves in: the first entry
// whose families cover the watch wins, and the poll — which never fails —
// is always last.
var autoOrder = []string{"connector", "poll"}

// Open selects a source. The process view prefers the kernel's proc connector
// and falls back to the /proc poll when the kernel or the container refuses the
// subscription. The socket view's auto is the sock_diag poll: it is the source
// that can name the owning process, which is the reason to watch sockets;
// conntrack's flow events carry no owner and stay behind --source conntrack.
func Open(ctx context.Context, family Family, opt Options) (Source, error) {
	if opt.Backend == "" || opt.Backend == "auto" {
		for _, word := range autoOrder {
			entry := backends[word]
			if entry.families&familyBits(family) == 0 {
				continue
			}
			if source, err := entry.new(ctx, family, opt); err == nil {
				return source, nil
			}
		}
		// The poll never fails; it is the answer even when every push
		// source above refused.
		source, _ := newPoll(ctx, family, opt)
		return source, nil
	}
	entry, ok := backends[opt.Backend]
	if !ok {
		return nil, fmt.Errorf("unknown watch source %q; use %s", opt.Backend, backendWords())
	}
	if entry.planned {
		return nil, fmt.Errorf("watch source %q is not available yet; use --source auto", opt.Backend)
	}
	if entry.families&familyBits(family) == 0 {
		return nil, fmt.Errorf("the %s source watches %s only", opt.Backend, familyWords(entry.families))
	}
	source, err := entry.new(ctx, family, opt)
	if err != nil {
		return nil, fmt.Errorf("%s unavailable: %w", opt.Backend, err)
	}
	return source, nil
}

// backendWords lists the source words Open accepts, for the refusal sentence.
func backendWords() string {
	words := []string{"auto"}
	for word, entry := range backends {
		if !entry.planned {
			words = append(words, word)
		}
	}
	slices.Sort(words[1:])
	return strings.Join(words, "|")
}

// familyWords names the families a mask covers.
func familyWords(families uint8) string {
	words := make([]string, 0, 2)
	for _, family := range []Family{FamilyProcess, FamilySocket} {
		if families&familyBits(family) != 0 {
			words = append(words, familyPlural(family))
		}
	}
	return strings.Join(words, " and ")
}

func newPoll(_ context.Context, family Family, opt Options) (Source, error) {
	if opt.Interval <= 0 {
		opt.Interval = DefaultInterval(family)
	}
	if family == FamilySocket {
		return &socketPoll{interval: opt.Interval, all: opt.All}, nil
	}
	return &procPoll{interval: opt.Interval, all: opt.All}, nil
}
