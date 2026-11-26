package audit

// The clock is part of the evidence. Every origin compares a ctime with a
// boundary; a host whose clock moved after boot can hide a late file under a
// package boundary or turn base files into runtime ones. This file reads the
// kernel's own two clocks and states the inconsistency.

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ClockState is the boundary-integrity reading: the wall clock now, the
// kernel's boot stamp and uptime, and the difference between the two.
type ClockState struct {
	Now     time.Time     `json:"now,omitempty"`
	Boot    time.Time     `json:"boot,omitempty"`
	Uptime  time.Duration `json:"uptime,omitempty"`
	Skew    time.Duration `json:"skew,omitempty"`
	Reading string        `json:"reading,omitempty"`
}

// clockTolerance is the slack between btime + uptime and now. NTP steps at
// boot and virtualized clocks move by seconds; minutes mean the wall clock
// was set after boot.
const clockTolerance = 5 * time.Minute

// clockHostileSkew is the skew that reads as hostile rather than as drift: a
// paused or stepped VM resumes hours off, and a medium-sized lie still gets
// the Medium it earns; a shift of more than six hours is the shape of an
// attacker moving the wall clock past the artifact boundary.
const clockHostileSkew = 6 * time.Hour

// readClockState reads /proc/uptime and /proc/stat's btime.
func readClockState() ClockState {
	state := ClockState{Now: time.Now()}
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			if seconds, err := strconv.ParseFloat(fields[0], 64); err == nil {
				state.Uptime = time.Duration(seconds * float64(time.Second))
			}
		}
	}
	if data, err := os.ReadFile("/proc/stat"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			value, ok := strings.CutPrefix(line, "btime ")
			if !ok {
				continue
			}
			if seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil {
				state.Boot = time.Unix(seconds, 0)
			}
		}
	}
	if !state.Boot.IsZero() && state.Uptime > 0 {
		state.Skew = state.Now.Sub(state.Boot.Add(state.Uptime))
		state.Reading = fmt.Sprintf("kernel boot %s + uptime %s = %s; wall clock %s",
			state.Boot.Format(stampLayout), state.Uptime.Round(time.Second),
			state.Boot.Add(state.Uptime).Format(stampLayout), state.Now.Format(stampLayout))
	}
	return state
}

// judgeClock states a clock that moved after boot, a boundary in the future,
// and object ctimes the wall clock has not reached. The first two make every
// time comparison suspect; the third names the objects that carry the
// inconsistency.
func judgeClock(snapshot *Snapshot, filter Filter, add func(Finding)) {
	if !globalScope(filter) {
		return
	}
	clock := snapshot.Clock
	if clock.Now.IsZero() {
		return
	}
	if clock.Skew > clockTolerance || clock.Skew < -clockTolerance {
		severity := Medium
		if clock.Skew > clockHostileSkew || clock.Skew < -clockHostileSkew {
			severity = High
		}
		add(Finding{
			Class: "clock-skew", Severity: severity,
			Title: "wall clock moved after boot",
			Path:  "/proc/stat", Origin: Unknown, Reach: KernelAsset,
			Detail:   fmt.Sprintf("btime + uptime differs from now by %s", clock.Skew.Round(time.Second)),
			Evidence: []string{clock.Reading, "time judgments compare ctimes with a boundary; a moved clock weakens them"},
			Trace:    steps("kernel btime", "uptime", "wall clock"),
		})
	}
	if !snapshot.Boundary.Time.IsZero() && snapshot.Boundary.Time.After(clock.Now.Add(clockTolerance)) {
		add(Finding{
			Class: "clock-boundary", Severity: Medium,
			Title: "artifact boundary is in the future",
			Path:  "/proc/stat", Origin: Unknown, Reach: KernelAsset,
			Detail: fmt.Sprintf("boundary %s is %s ahead of the wall clock",
				snapshot.Boundary.Time.Format(stampLayout), snapshot.Boundary.Time.Sub(clock.Now).Round(time.Second)),
			Evidence: []string{
				fmt.Sprintf("boundary source %s (%s)", snapshot.Boundary.Source, snapshot.Boundary.Kind),
				fmt.Sprintf("wall clock %s", clock.Now.Format(stampLayout)),
			},
			Trace: steps("artifact boundary", "wall clock"),
		})
	}
	limit := clock.Now.Add(clockTolerance).Unix()
	var future []string
	for path, facts := range snapshot.Objects {
		if facts.CTime > limit {
			future = append(future, path)
		}
	}
	sort.Strings(future)
	const shown = 20
	for index, path := range future {
		if index == shown {
			add(Finding{
				Class: "future-timestamp", Severity: Low,
				Title: "more file timestamps are in the future",
				Path:  future[0], Origin: Unknown, Reach: NoAsset,
				Detail:   fmt.Sprintf("the report stops naming future-stamped objects at %d", shown),
				Evidence: []string{"a ctime ahead of the wall clock cannot be trusted"},
			})
			break
		}
		facts := snapshot.Objects[path]
		add(Finding{
			Class: "future-timestamp", Severity: Medium,
			Title: "file change time is in the future",
			Path:  path, Origin: Unknown, Reach: NoAsset,
			Detail: fmt.Sprintf("ctime %s is ahead of the wall clock %s",
				ctimeString(facts.CTime), clock.Now.Format(stampLayout)),
			Evidence: []string{"the file was created or changed by a clock that is ahead of this one"},
			Trace:    steps(path, "ctime", "wall clock"),
		})
	}
}
