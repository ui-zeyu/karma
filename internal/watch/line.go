package watch

import (
	"strconv"
	"strings"

	chrome "karma/internal/panel"
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
	switch {
	case ev.Proc != nil:
		lineProc(&b, ev, ev.Proc)
	case ev.Sock != nil:
		lineSock(&b, ev, ev.Sock)
	}
	if ev.Source != "" {
		b.WriteString(" source=")
		b.WriteString(string(ev.Source))
	}
	if ev.Verdict != nil {
		b.WriteString(" origin=")
		b.WriteString(ev.Verdict.Origin.String())
		b.WriteString(" reach=")
		b.WriteString(ev.Verdict.Reach.String())
		b.WriteString(" severity=")
		b.WriteString(ev.Verdict.Severity.String())
	}
	if len(ev.Flags) > 0 {
		b.WriteString(" flags=")
		for index, flag := range ev.Flags {
			if index > 0 {
				b.WriteString(",")
			}
			b.WriteString(string(flag))
		}
	}
	return strings.TrimRight(b.String(), " ")
}

func lineProc(b *strings.Builder, ev Event, proc *Proc) {
	b.WriteString(fmtKind(proc.Kind))
	b.WriteString(" pid=")
	b.WriteString(pidWord(proc.PID))
	b.WriteString(" ppid=")
	b.WriteString(strconv.Itoa(proc.PPID))
	b.WriteString(" uid=")
	b.WriteString(strconv.Itoa(proc.UID))
	if proc.Comm != "" {
		b.WriteString(" comm=")
		b.WriteString(chrome.SafeText(proc.Comm))
	}
	if proc.Kind == KindExit && proc.ExitCode != nil {
		b.WriteString(" code=")
		b.WriteString(strconv.Itoa(*proc.ExitCode))
	}
	if proc.Exe != "" {
		b.WriteString(" exe=")
		b.WriteString(chrome.SafeText(proc.Exe))
	}
	if proc.Cmdline != "" {
		b.WriteString(" cmdline=")
		b.WriteString(strconv.Quote(proc.Cmdline))
	}
	if proc.Script != "" {
		b.WriteString(" script=")
		b.WriteString(chrome.SafeText(proc.Script))
	}
	if proc.Cwd != "" {
		b.WriteString(" cwd=")
		b.WriteString(chrome.SafeText(proc.Cwd))
	}
}

func lineSock(b *strings.Builder, ev Event, sock *Sock) {
	b.WriteString("socket ")
	b.WriteString(sock.Net.Proto)
	b.WriteString(" ")
	b.WriteString(fmtSlice(sock.Net.State, 9))
	b.WriteString(" ")
	b.WriteString(sock.Net.Local)
	b.WriteString(" -> ")
	b.WriteString(sock.Net.Peer)
	b.WriteString(" pid=")
	b.WriteString(pidWord(sock.PID))
	if sock.Comm != "" {
		b.WriteString(" comm=")
		b.WriteString(chrome.SafeText(sock.Comm))
	}
	if sock.Exe != "" {
		b.WriteString(" exe=")
		b.WriteString(chrome.SafeText(sock.Exe))
	}
	if sock.Script != "" {
		b.WriteString(" script=")
		b.WriteString(chrome.SafeText(sock.Script))
	}
	if sock.Cwd != "" {
		b.WriteString(" cwd=")
		b.WriteString(chrome.SafeText(sock.Cwd))
	}
}

// fmtKind pads the kind cell to the width the socket row's protocol column
// implies, so the two views align.
func fmtKind(kind Kind) string {
	return fmtSlice(string(kind), 6)
}

func fmtSlice(value string, width int) string {
	if len(value) >= width {
		return value
	}
	return value + strings.Repeat(" ", width-len(value))
}

// pidWord is a pid cell; 0 is no local owner, which a socket's TIME-WAIT row
// carries.
func pidWord(pid int) string {
	if pid <= 0 {
		return "-"
	}
	return strconv.Itoa(pid)
}
