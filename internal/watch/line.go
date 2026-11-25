package watch

import (
	"fmt"
	"strconv"
	"strings"
)

// timeLayout is the report's live-event stamp: local time with milliseconds,
// enough to order events from one poll tick.
const timeLayout = "2006-01-02 15:04:05.000"

// Line renders one event as a single line. Fields are appended in a fixed
// order and empty ones are omitted, so a process event and a socket event read
// the same way they are grepped.
func Line(ev Event) string {
	var b strings.Builder
	b.WriteString(ev.Time.Format(timeLayout))
	b.WriteString("  ")
	b.WriteString(fmt.Sprintf("%-6s", ev.Kind))
	if ev.Kind == KindSocket && ev.Net != nil {
		b.WriteString(" ")
		b.WriteString(ev.Net.Proto)
		b.WriteString(" ")
		b.WriteString(fmt.Sprintf("%-9s", ev.Net.State))
		b.WriteString(" ")
		b.WriteString(ev.Net.Local)
		b.WriteString(" -> ")
		b.WriteString(ev.Net.Peer)
	}
	b.WriteString(" pid=")
	b.WriteString(pidWord(ev.PID))
	if ev.Kind != KindSocket {
		b.WriteString(" ppid=")
		b.WriteString(strconv.Itoa(ev.PPID))
		b.WriteString(" uid=")
		b.WriteString(strconv.Itoa(ev.UID))
	}
	if ev.Comm != "" {
		b.WriteString(" comm=")
		b.WriteString(ev.Comm)
	}
	if ev.Kind == KindExit && ev.ExitCode != nil {
		b.WriteString(" code=")
		b.WriteString(strconv.Itoa(*ev.ExitCode))
	}
	if ev.Exe != "" {
		b.WriteString(" exe=")
		b.WriteString(ev.Exe)
	}
	if ev.Cmdline != "" {
		b.WriteString(" cmdline=")
		b.WriteString(strconv.Quote(ev.Cmdline))
	}
	if ev.Cwd != "" {
		b.WriteString(" cwd=")
		b.WriteString(ev.Cwd)
	}
	if ev.Source != "" {
		b.WriteString(" source=")
		b.WriteString(ev.Source)
	}
	if ev.Origin != "" {
		b.WriteString(" origin=")
		b.WriteString(ev.Origin)
		b.WriteString(" reach=")
		b.WriteString(ev.Reach)
		b.WriteString(" severity=")
		b.WriteString(ev.Severity)
	}
	if len(ev.Flags) > 0 {
		b.WriteString(" flags=")
		b.WriteString(strings.Join(ev.Flags, ","))
	}
	return b.String()
}

// pidWord is a pid cell; 0 is no local owner, which a socket's TIME-WAIT row
// carries.
func pidWord(pid int) string {
	if pid <= 0 {
		return "-"
	}
	return strconv.Itoa(pid)
}
