package facts_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"karma/internal/facts"
	"karma/internal/model"
	"karma/internal/powershell"
	"karma/internal/session"
)

// scriptedSession replays results by call content. Fact collection is concurrent, so
// canned answers cannot be taken in arrival order.
type scriptedSession struct {
	mu    sync.Mutex
	calls []string
	reply func(model.Invocation) model.RunResult
}

func (s *scriptedSession) Name() string { return "scripted" }

func (s *scriptedSession) Channel() model.Channel { return model.ChanSSH }

func (s *scriptedSession) Close() error { return nil }

func (s *scriptedSession) Run(_ context.Context, inv model.Invocation, _ time.Duration, _ int) model.RunResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch v := inv.(type) {
	case model.Shell:
		s.calls = append(s.calls, "sh:"+firstLine(v.Script))
	case model.Command:
		s.calls = append(s.calls, strings.Join(v.Argv, " "))
	}
	return s.reply(inv)
}

func (s *scriptedSession) joinedCalls() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.calls, "\n")
}

func firstLine(text string) string {
	head, _, _ := strings.Cut(text, "\n")
	return head
}

func scriptOf(inv model.Invocation) string {
	cmd, ok := inv.(model.Command)
	if !ok || len(cmd.Argv) == 0 {
		return ""
	}
	return cmd.Argv[len(cmd.Argv)-1]
}

func TestCollectLinux(t *testing.T) {
	fake := &scriptedSession{reply: func(inv model.Invocation) model.RunResult {
		switch v := inv.(type) {
		case model.Shell:
			switch {
			case strings.Contains(v.Script, "for name in"):
				return model.RunResult{Stdout: "/usr/bin/hostname\n/usr/bin/uname\n/usr/bin/id\n", ExitCode: 0}
			case strings.Contains(v.Script, "hostname"):
				return model.RunResult{Stdout: "web-01\n", ExitCode: 0}
			case strings.Contains(v.Script, "os-release"):
				return model.RunResult{Stdout: "PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\n", ExitCode: 0}
			}
		case model.Command:
			switch v.Argv[0] {
			case "uname":
				return model.RunResult{Stdout: "5.15.0-91-generic\n", ExitCode: 0}
			case "id":
				return model.RunResult{Stdout: "0\n", ExitCode: 0}
			}
		}
		t.Errorf("unexpected call: %+v", inv)
		return model.RunResult{ExitCode: 1}
	}}
	got := facts.Collect(context.Background(), fake, []string{"find"})
	if got.AvailableBins["find"] {
		t.Fatalf("find missing from probe output: %+v", got.AvailableBins)
	}
	if !got.AvailableBins["hostname"] || !got.AvailableBins["uname"] || !got.AvailableBins["id"] {
		t.Fatalf("wrong capability bits: %+v", got.AvailableBins)
	}
	if got.Hostname != "web-01" || got.Kernel != "5.15.0-91-generic" {
		t.Fatalf("wrong host facts: %+v", got)
	}
	if got.OsPretty != "Ubuntu 22.04.3 LTS" || got.UID != 0 || !got.IsRoot() {
		t.Fatalf("wrong host facts: %+v", got)
	}
	if !strings.Contains(fake.joinedCalls(), "for name in") {
		t.Fatalf("capability probe should be a for loop: %q", fake.joinedCalls())
	}
}

func TestCollectWindowsPowershellPresent(t *testing.T) {
	fake := &scriptedSession{reply: func(inv model.Invocation) model.RunResult {
		script := scriptOf(inv)
		switch {
		case strings.Contains(script, "Get-Command"):
			return model.RunResult{Stdout: "powershell\nreg\n", ExitCode: 0}
		case strings.Contains(script, "USERDOMAIN"):
			return model.RunResult{Stdout: strings.Join([]string{
				"== host", "WS2019",
				"== user", `CORP\admin`,
				"== os", "Windows Server 2019 Datacenter 1809",
				"== kernel", "10.0.17763.4252",
			}, "\n") + "\n", ExitCode: 0}
		default:
			t.Errorf("unexpected call: %+v", inv)
			return model.RunResult{ExitCode: 1}
		}
	}}
	got := facts.CollectWindows(context.Background(), fake, nil)
	if got.Hostname != "WS2019" || got.User != "CORP\\admin" {
		t.Fatalf("wrong host facts: %+v", got)
	}
	if got.Kernel != "10.0.17763.4252" || got.UID != -1 {
		t.Fatalf("wrong host facts: %+v", got)
	}
	if got.OsPretty != "Windows Server 2019 Datacenter 1809" {
		t.Fatalf("wrong OS name: %q", got.OsPretty)
	}
	if !got.AvailableBins["powershell"] || !got.AvailableBins["reg"] {
		t.Fatalf("wrong capability bits: %+v", got.AvailableBins)
	}
	// PS cold start is expensive: capability probe + facts are two paths, the other four are merged into one sectioned output
	if calls := strings.Count(fake.joinedCalls(), "powershell -NoProfile"); calls != 2 {
		t.Fatalf("with PS present there should be exactly 2 PS calls: %d", calls)
	}
	first := strings.Split(fake.joinedCalls(), "\n")[0]
	if !strings.HasPrefix(first, "powershell -NoProfile") || !strings.Contains(first, powershell.UTF8Prefix[:10]) {
		t.Fatalf("capability probe should be a PS argument vector: %q", first)
	}
}

// CurrentVersion key unreadable: os/kernel sections absent, fall back to defaults, other facts unaffected.
func TestCollectWindowsPowershellDegraded(t *testing.T) {
	fake := &scriptedSession{reply: func(inv model.Invocation) model.RunResult {
		script := scriptOf(inv)
		switch {
		case strings.Contains(script, "Get-Command"):
			return model.RunResult{Stdout: "powershell\n", ExitCode: 0}
		case strings.Contains(script, "USERDOMAIN"):
			return model.RunResult{Stdout: "== host\nWIN-XP\n== user\nBOX\\john\n", ExitCode: 0}
		default:
			t.Errorf("unexpected call: %+v", inv)
			return model.RunResult{ExitCode: 1}
		}
	}}
	got := facts.CollectWindows(context.Background(), fake, nil)
	if got.Hostname != "WIN-XP" || got.User != "BOX\\john" {
		t.Fatalf("wrong host facts: %+v", got)
	}
	if got.Kernel != "" || got.OsPretty != "unknown version" {
		t.Fatalf("absent facts should fall back: %+v", got)
	}
}

func TestCollectWindowsFallsBackToRegistry(t *testing.T) {
	currentVersion := strings.Join([]string{
		"",
		`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		"    CurrentVersion    REG_SZ    5.1",
		"    CurrentBuildNumber    REG_SZ    2600",
		"    ProductName    REG_SZ    Microsoft Windows XP",
		"    UBR    REG_DWORD    0x1000",
		"",
	}, "\n")
	fake := &scriptedSession{reply: func(inv model.Invocation) model.RunResult {
		cmd, ok := inv.(model.Command)
		if !ok {
			t.Errorf("fallback tier should be an argument vector: %+v", inv)
			return model.RunResult{ExitCode: 1}
		}
		joined := strings.Join(cmd.Argv, " ")
		switch {
		case cmd.Argv[0] == "powershell":
			return model.RunResult{ExitCode: -1, Stderr: "channel timeout"}
		case strings.Contains(joined, "CurrentVersion") && !strings.Contains(joined, "/v"):
			return model.RunResult{Stdout: currentVersion, ExitCode: 0}
		case strings.Contains(joined, "ComputerName"):
			return model.RunResult{Stdout: "\n    ComputerName    REG_SZ    OLD-XP\n", ExitCode: 0}
		case strings.Contains(joined, "USERNAME"):
			return model.RunResult{Stdout: "\n    USERNAME    REG_SZ    john\n", ExitCode: 0}
		default:
			t.Errorf("unexpected call: %s", joined)
			return model.RunResult{ExitCode: 1}
		}
	}}
	got := facts.CollectWindows(context.Background(), fake, nil)
	if !got.AvailableBins["reg"] || got.AvailableBins["powershell"] {
		t.Fatalf("after fallback only reg should be in capability bits: %+v", got.AvailableBins)
	}
	if got.Hostname != "OLD-XP" || got.User != "john" {
		t.Fatalf("wrong registry facts: %+v", got)
	}
	if got.Kernel != "5.1.2600.4096" {
		t.Fatalf("wrong kernel join: %q", got.Kernel)
	}
	if got.OsPretty != "Microsoft Windows XP" {
		t.Fatalf("wrong OS name: %q", got.OsPretty)
	}
}

var _ session.Session = (*scriptedSession)(nil)
