package facts_test

import (
	"context"
	"strings"
	"sync"
	"testing"

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

func (s *scriptedSession) Describe() string { return "scripted" }

func (s *scriptedSession) Close() error { return nil }

func (s *scriptedSession) Run(_ context.Context, call model.Call) model.RunResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch v := call.Inv.(type) {
	case model.Shell:
		s.calls = append(s.calls, "sh:"+firstLine(v.Script))
	case model.Command:
		s.calls = append(s.calls, strings.Join(v.Argv, " "))
	}
	return s.reply(call.Inv)
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
				return model.RunResult{Stdout: "/usr/bin/hostname\n/usr/bin/uname\n/usr/bin/id\n", Verdict: model.VerdictAnswered}
			case strings.Contains(v.Script, "hostname"):
				return model.RunResult{Verdict: model.VerdictAnswered, Stdout: "web-01\n"}
			case strings.Contains(v.Script, "os-release"):
				return model.RunResult{Verdict: model.VerdictAnswered, Stdout: "PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\n"}
			}
		case model.Command:
			switch v.Argv[0] {
			case "uname":
				return model.RunResult{Verdict: model.VerdictAnswered, Stdout: "5.15.0-91-generic\n"}
			case "id":
				return model.RunResult{Verdict: model.VerdictAnswered, Stdout: "0\n"}
			}
		}
		t.Errorf("unexpected call: %+v", inv)
		return model.RunResult{Verdict: model.VerdictFailed, ExitCode: 1}
	}}
	got := facts.Collect(context.Background(), fake)
	if got.Hostname != "web-01" || got.Kernel != "5.15.0-91-generic" {
		t.Fatalf("wrong host facts: %+v", got)
	}
	if got.OsPretty != "Ubuntu 22.04.3 LTS" || got.UID != 0 || !got.IsRoot() {
		t.Fatalf("wrong host facts: %+v", got)
	}
	// The capability probe searches exactly this package's own names, one PATH
	// search per name in a for loop: a check's tiers are not part of it, so no
	// name a catalog carries can appear here.
	if !strings.Contains(fake.joinedCalls(), "for name in") {
		t.Fatalf("capability probe should be a for loop: %q", fake.joinedCalls())
	}
	for _, name := range []string{"'hostname'", "'id'", "'uname'"} {
		if !strings.Contains(fake.joinedCalls(), name) {
			t.Errorf("the probe should search %s: %q", name, fake.joinedCalls())
		}
	}
	if strings.Contains(fake.joinedCalls(), "'find'") {
		t.Errorf("the probe should search only this package's names: %q", fake.joinedCalls())
	}
}

func TestCollectWindowsPowershellPresent(t *testing.T) {
	fake := &scriptedSession{reply: func(inv model.Invocation) model.RunResult {
		script := scriptOf(inv)
		switch {
		case strings.Contains(script, "Get-Command"):
			return model.RunResult{Verdict: model.VerdictAnswered, Stdout: "powershell\nreg\n"}
		case strings.Contains(script, "USERDOMAIN"):
			return model.RunResult{Stdout: strings.Join([]string{
				"== host", "WS2019",
				"== user", `CORP\admin`,
				"== os", "Windows Server 2019 Datacenter 1809",
				"== kernel", "10.0.17763.4252",
			}, "\n") + "\n"}
		default:
			t.Errorf("unexpected call: %+v", inv)
			return model.RunResult{Verdict: model.VerdictFailed, ExitCode: 1}
		}
	}}
	got := facts.CollectWindows(context.Background(), fake)
	if got.Hostname != "WS2019" || got.User != "CORP\\admin" {
		t.Fatalf("wrong host facts: %+v", got)
	}
	if got.Kernel != "10.0.17763.4252" || got.UID != -1 {
		t.Fatalf("wrong host facts: %+v", got)
	}
	if got.OsPretty != "Windows Server 2019 Datacenter 1809" {
		t.Fatalf("wrong OS name: %q", got.OsPretty)
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
			return model.RunResult{Verdict: model.VerdictAnswered, Stdout: "powershell\n"}
		case strings.Contains(script, "USERDOMAIN"):
			return model.RunResult{Verdict: model.VerdictAnswered, Stdout: "== host\nWIN-XP\n== user\nBOX\\john\n"}
		default:
			t.Errorf("unexpected call: %+v", inv)
			return model.RunResult{Verdict: model.VerdictFailed, ExitCode: 1}
		}
	}}
	got := facts.CollectWindows(context.Background(), fake)
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
			return model.RunResult{Verdict: model.VerdictFailed, ExitCode: 1}
		}
		joined := strings.Join(cmd.Argv, " ")
		switch {
		case cmd.Argv[0] == "powershell":
			return model.RunResult{Verdict: model.VerdictTimedOut, Stderr: "channel timeout", ExitCode: -1}
		case strings.Contains(joined, "CurrentVersion") && !strings.Contains(joined, "/v"):
			return model.RunResult{Verdict: model.VerdictAnswered, Stdout: currentVersion}
		case strings.Contains(joined, "ComputerName"):
			return model.RunResult{Verdict: model.VerdictAnswered, Stdout: "\n    ComputerName    REG_SZ    OLD-XP\n"}
		case strings.Contains(joined, "USERNAME"):
			return model.RunResult{Verdict: model.VerdictAnswered, Stdout: "\n    USERNAME    REG_SZ    john\n"}
		default:
			t.Errorf("unexpected call: %s", joined)
			return model.RunResult{Verdict: model.VerdictFailed, ExitCode: 1}
		}
	}}
	got := facts.CollectWindows(context.Background(), fake)
	// The registry path is the observable half of "there is no PowerShell here":
	// every fact comes from a reg query, and the one PS cold start that would
	// have brought them back (the USERDOMAIN script, whose probe timed out) never
	// ran.
	if !strings.Contains(fake.joinedCalls(), "reg query") {
		t.Errorf("the fallback should read the registry: %q", fake.joinedCalls())
	}
	if strings.Contains(fake.joinedCalls(), "USERDOMAIN") {
		t.Errorf("the fallback should not run the PS facts script: %q", fake.joinedCalls())
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
