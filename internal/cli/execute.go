// The audit run: collect one snapshot, judge it, and render the findings.

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"karma/internal/audit"
)

// runAudit is the default action of the command and of `karma audit`.
func runAudit(ctx context.Context, w io.Writer, words []string, flags auditFlags) error {
	parsed, err := parseScope(words)
	if err != nil {
		return usagef(nil, "%s", err)
	}
	snapshot, collectErr := collectSnapshot(ctx, parsed.plan(), flags.timeout, flags.json)
	if snapshot == nil {
		return collectErr
	}
	if err := applySince(snapshot, flags.since); err != nil {
		return err
	}
	report := audit.Judge(snapshot, parsed.filter(flags.minSeverity))
	if flags.json {
		if err := audit.WriteJSON(w, report); err != nil {
			return err
		}
		return collectErr
	}
	audit.Render(w, report, renderOptions(w, flags, parsed.filter(audit.Info)))
	return collectErr
}

// runShow prints one collected inventory without judging it.
func runShow(ctx context.Context, w io.Writer, words []string, flags auditFlags) error {
	section := words[0]
	if !audit.IsShowWord(section) {
		return usagef(nil, "unknown show target %q (%s)", section, strings.Join(audit.ShowWords(), ", "))
	}
	parsed, err := parseScope(words[1:])
	if err != nil {
		return usagef(nil, "%s", err)
	}
	plan, _ := audit.ShowPlan(section, parsed.plan())
	snapshot, collectErr := collectSnapshot(ctx, plan, flags.timeout, flags.json)
	if snapshot == nil {
		return collectErr
	}
	options := audit.RenderOptions{
		Version: buildVersion, Color: isTerminal(w), Evidence: flags.evidence,
		Width: terminalWidth(w), Filter: parsed.filter(audit.Info),
	}
	if flags.json {
		if err := audit.WriteShowJSON(w, snapshot, section, options); err != nil {
			return err
		}
		return collectErr
	}
	audit.RenderShow(w, snapshot, section, options)
	return collectErr
}

// runObjectGraph prints one object's relation graph and the findings that touch it.
func runObjectGraph(ctx context.Context, w io.Writer, word string, flags auditFlags) error {
	plan := audit.ProfilePlan()
	plan.Profile = word
	if unit := profileUnitSelector(word); unit != "" {
		plan.ProfileUnit = unit
		plan.Surfaces = map[string]bool{"systemd": true}
		plan.Domains = audit.DomainBase | audit.DomainServices | audit.DomainProcesses | audit.DomainNetwork
	} else if pid, ok := profilePIDSelector(word); ok {
		plan.ProfilePIDs = map[int]bool{pid: true}
		plan.Surfaces = map[string]bool{}
		plan.Domains = audit.DomainBase | audit.DomainProcesses | audit.DomainNetwork
	} else {
		plan.Surfaces = nil
		plan.Domains = audit.DomainBase | audit.DomainPersistence
	}
	snapshot, collectErr := collectSnapshot(ctx, plan, flags.timeout, flags.json)
	if snapshot == nil {
		return collectErr
	}
	if err := applySince(snapshot, flags.since); err != nil {
		return err
	}
	profile, err := audit.BuildProfile(ctx, snapshot, word, flags.minSeverity)
	if err != nil {
		return usagef(nil, "%s", err)
	}
	if flags.json {
		if err := audit.WriteGraphJSON(w, profile); err != nil {
			return err
		}
		return collectErr
	}
	audit.RenderGraph(w, profile, renderOptions(w, flags, audit.Filter{MinSeverity: flags.minSeverity}))
	return collectErr
}

// collectSnapshot reads this host in process under the run's time budget. A
// stopped collection still returns the snapshot it read, so the operator sees
// the partial answer and the exit status states why it stopped. The progress
// band lives here, not at the call sites: every collecting command gets the
// same line, the same interrupt state and the same quiet JSON behavior by
// construction. quiet suppresses the band for machine output.
func collectSnapshot(ctx context.Context, plan audit.Plan, budget time.Duration, quiet bool) (*audit.Snapshot, error) {
	p := newProgress(quiet)
	p.watch(ctx)
	defer p.done()
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	snapshot, err := audit.CollectLocal(ctx, plan, stageProgress(p))
	if err == nil {
		return snapshot, nil
	}
	switch {
	case errors.Is(err, context.Canceled):
		return snapshot, failf(ExitInterrupted, "collection interrupted: %v", err)
	case errors.Is(err, context.DeadlineExceeded):
		return snapshot, failf(ExitEnvironment, "collection timed out: %v", err)
	default:
		return snapshot, failf(ExitInternal, "collection: %v", err)
	}
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

// profileUnitSelector names the unit a profile word selects, or "" when the
// word is a pid, path or package.
func profileUnitSelector(word string) string {
	if value, ok := strings.CutPrefix(word, "unit:"); ok {
		return value
	}
	value := word
	switch {
	case strings.HasSuffix(value, ".service"), strings.HasSuffix(value, ".socket"),
		strings.HasSuffix(value, ".timer"), strings.HasSuffix(value, ".path"),
		strings.HasSuffix(value, ".target"), strings.HasSuffix(value, ".mount"):
		return value
	}
	return ""
}

// profilePIDSelector reads a pid word, with or without the pid: prefix.
func profilePIDSelector(word string) (int, bool) {
	value := strings.TrimPrefix(word, "pid:")
	if value == "" {
		return 0, false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	pid, err := strconv.Atoi(value)
	return pid, err == nil
}

// sinceTime reads --since: empty and "auto" keep the collected boundary;
// "boot" and "provision" are the same boundary by another name; a duration
// answers now minus it; an RFC3339 stamp is absolute.
// applySince retargets a collected snapshot when --since names an edge.
func applySince(snapshot *audit.Snapshot, since string) error {
	seconds, ok, err := sinceTime(since)
	if err != nil {
		return usagef(nil, "%s", err)
	}
	if ok {
		snapshot.SetBoundary(audit.Boundary{
			Time: seconds, Kind: snapshot.Boundary.Kind, Source: "operator", Confidence: audit.HighConfidence,
		})
	}
	return nil
}

// renderOptions is the one place the text options are built.
func renderOptions(w io.Writer, flags auditFlags, filter audit.Filter) audit.RenderOptions {
	return audit.RenderOptions{
		Version:  buildVersion,
		Color:    isTerminal(w),
		Evidence: flags.evidence,
		Width:    terminalWidth(w),
		Filter:   filter,
	}
}

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
