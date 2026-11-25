// The audit run: collect one snapshot, judge it, and render the findings.

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/term"

	"karma/internal/audit"
)

// runAudit is the default action of the command and of `karma audit`.
func runAudit(ctx context.Context, w io.Writer, words []string, flags auditFlags) error {
	parsed, err := parseScope(words)
	if err != nil {
		return err
	}
	snapshot, err := collectSnapshot(ctx, flags.timeout)
	if err != nil {
		return err
	}
	if seconds, ok, err := sinceTime(flags.since); err != nil {
		return err
	} else if ok {
		snapshot.Boundary = audit.Boundary{
			Time: seconds, Kind: snapshot.Boundary.Kind, Source: "operator", Confidence: audit.HighConfidence,
		}
	}
	report := audit.Judge(snapshot, parsed.filter(flags.minSeverity))
	if flags.json {
		return audit.WriteJSON(w, report)
	}
	audit.Render(w, report, snapshot, audit.RenderOptions{
		Version:  buildVersion,
		Color:    isTerminal(w),
		Evidence: flags.evidence,
		Width:    terminalWidth(w),
		Filter:   parsed.filter(audit.Info),
	})
	return nil
}

// runShow prints one collected inventory without judging it.
func runShow(ctx context.Context, w io.Writer, words []string, flags auditFlags) error {
	if len(words) == 0 {
		fmt.Fprintln(w, "show: activation | process | services | listeners | authority | mounts | coverage")
		return nil
	}
	section := words[0]
	switch section {
	case "activation", "persistence", "boot", "login", "service", "device", "schedule",
		"process", "activity", "services", "listeners", "sockets", "listen", "authority", "mounts", "coverage":
	default:
		return fmt.Errorf("unknown show target %q (activation, process, services, listeners, authority, mounts, coverage)", section)
	}
	parsed, err := parseScope(words[1:])
	if err != nil {
		return err
	}
	snapshot, err := collectSnapshot(ctx, flags.timeout)
	if err != nil {
		return err
	}
	audit.RenderShow(w, snapshot, section, audit.RenderOptions{
		Version: buildVersion, Color: isTerminal(w), Evidence: true,
		Width: terminalWidth(w), Filter: parsed.filter(audit.Info),
	})
	return nil
}

// collectSnapshot reads this host in process under the run's time budget.
func collectSnapshot(ctx context.Context, budget time.Duration) (*audit.Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	snapshot, err := audit.CollectLocal(ctx)
	if err != nil {
		return nil, failf(ExitInternal, "collection: %v", err)
	}
	return snapshot, nil
}

// auditFlags are the run options the audit and show modes share.
type auditFlags struct {
	json        bool
	evidence    bool
	minSeverity audit.Severity
	since       string
	timeout     time.Duration
}

func isTerminal(w io.Writer) bool {
	file, ok := w.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

func terminalWidth(w io.Writer) int {
	file, ok := w.(*os.File)
	if !ok {
		return 100
	}
	if size, _, err := term.GetSize(int(file.Fd())); err == nil && size > 0 {
		return size
	}
	return 100
}

// sinceTime reads --since: empty and "auto" keep the collected boundary;
// "boot" and "provision" are the same boundary by another name; a duration
// answers now minus it; an RFC3339 stamp is absolute.
func sinceTime(value string) (time.Time, bool, error) {
	switch value {
	case "", "auto", "boot", "provision":
		return time.Time{}, false, nil
	}
	if duration, err := time.ParseDuration(value); err == nil {
		return time.Now().Add(-duration), true, nil
	}
	if stamp, err := time.Parse(time.RFC3339, value); err == nil {
		return stamp, true, nil
	}
	return time.Time{}, false, fmt.Errorf("--since needs a duration, boot, provision, or an RFC3339 time (got: %s)", value)
}
