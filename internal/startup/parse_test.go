package startup

// The parsers' behavior, pinned one mechanism at a time. Each case is a line a
// real host carries; the assertions state the edge the parser must answer with,
// so a parser change that loses an activation has to break a named case first.

import (
	"context"
	"testing"

	"karma/internal/trust"
)

// fileFacts answers every path a regular root-owned file.
func fileFacts(path string) trust.Facts {
	return trust.Build(path, trust.Attrs{Kind: trust.File, Mode: 0o755, UID: 0, Real: path})
}

// firstTarget answers the first target the parser stated, whatever kind: the
// callers assert the target they expect and check the kind separately.
func firstTarget(edges []rawEdge) string {
	for _, edge := range edges {
		if edge.target != "" {
			return edge.target
		}
	}
	return ""
}

// mustShellEdges parses a test body and states its edges, failing the test
// when the shell grammar refuses the body.
func mustShellEdges(t *testing.T, body string, base rawEdge) []rawEdge {
	t.Helper()
	tree, err := parseShellBody(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return shellEdges(base, tree, body)
}

func TestShellEdgesKnowTheStatements(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
		kind Kind
	}{
		{"source", "source /opt/vendor/env.sh\n", "/opt/vendor/env.sh", Source},
		{"dot", ". /opt/vendor/env.sh\n", "/opt/vendor/env.sh", Source},
		{"exec", "exec /opt/agent --serve\n", "/opt/agent", Exec},
		{"absolute command", "/opt/agent --serve\n", "/opt/agent", Exec},
		{"export preload", "export LD_PRELOAD=/opt/hook.so\n", "/opt/hook.so", Preload},
		{"export audit", "export LD_AUDIT=/opt/hook.so\n", "/opt/hook.so", Preload},
		{"export file value", "export APP_HOME=/opt/agent/home\n", "/opt/agent/home", Env},
		{"plain assignment", "APP_HOME=/opt/agent/home\n", "/opt/agent/home", Env},
		{"quoted command", "\"/opt/space dir/agent\"\n", "/opt/space dir/agent", Exec},
	}
	for _, test := range cases {
		edges := mustShellEdges(t, test.body, rawEdge{
			surface: SurfaceProfile, phase: Login, subject: Subject{Class: AccountLogin},
			trigger: "/etc/profile.d/x.sh",
		})
		got := firstTarget(edges)
		if got != test.want {
			t.Errorf("%s: target = %q, want %q (edges %+v)", test.name, got, test.want, edges)
			continue
		}
		for _, edge := range edges {
			if edge.target == test.want && edge.kind != test.kind {
				t.Errorf("%s: kind = %s, want %s", test.name, edge.kind, test.kind)
			}
		}
	}
}

func TestShellEdgesKeepDynamicTargetsHonest(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"a variable command is a PATH lookup", "$BIN --serve\n"},
		{"a relative command cannot be placed", "agent --serve\n"},
		{"an expanded assignment is not a path", "export APP_HOME=${PREFIX}/share\n"},
		{"a command substitution builds the path", "exec $(find /opt -name agent)\n"},
	}
	for _, test := range cases {
		edges := mustShellEdges(t, test.body, rawEdge{
			surface: SurfaceProfile, phase: Login, subject: Subject{Class: AccountLogin},
			trigger: "/etc/profile.d/x.sh",
		})
		for _, edge := range edges {
			if !edge.dynamic {
				t.Errorf("%s: edge %+v is stated as placeable", test.name, edge)
			}
		}
	}
}

func TestShellEdgesReadInsideConditions(t *testing.T) {
	// The parser reads the syntax, so a source inside an if the file happens
	// to skip at runtime is still an edge: the static read cannot know the
	// condition's value.
	body := "if [ -f /opt/vendor/env.sh ]; then\n  source /opt/vendor/env.sh\nfi\n"
	edges := mustShellEdges(t, body, rawEdge{trigger: "/etc/profile.d/x.sh"})
	if firstTarget(edges) != "/opt/vendor/env.sh" {
		t.Errorf("edges inside a condition = %+v", edges)
	}
}

func TestInterpreterCommandLines(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"a versioned interpreter carries its script", "/usr/bin/python3.11 /opt/agent/main.py\n", "/opt/agent/main.py"},
		{"inline code is parsed for its own references", "/usr/bin/bash -c 'source /opt/vendor/env.sh'\n", "/opt/vendor/env.sh"},
		{"a wrapper chain reaches the program", "/usr/bin/env -u X /usr/bin/nohup /opt/agent --serve\n", "/opt/agent"},
		{"sudo reaches the program", "/usr/bin/sudo -u agent /opt/agent\n", "/opt/agent"},
	}
	for _, test := range cases {
		edges := mustShellEdges(t, test.body, rawEdge{trigger: "/etc/cron.daily/x"})
		if got := firstTarget(edges); got != test.want {
			t.Errorf("%s: target = %q, want %q (%+v)", test.name, got, test.want, edges)
		}
	}
}

func TestUnitExecForms(t *testing.T) {
	body := "[Service]\n" +
		"ExecStart=-/opt/agent --serve\n" +
		"ExecStartPre=+/usr/sbin/prep --now\n" +
		"ExecReload=/bin/kill -HUP $MAINPID\n"
	corpus := NewCorpus(context.Background(), OSFS{}, []File{{
		Path: "/etc/systemd/system/agent.service", Unit: "agent.service",
		Surface: SurfaceSystemd, Dialect: UnitDialect, Body: body,
	}}, nil, fileFacts)
	edges := Analyze(corpus)
	got := map[string]string{}
	for _, edge := range edges {
		got[string(edge.Mechanism)] = edge.Target
	}
	if got["ExecStart"] != "/opt/agent" {
		t.Errorf("ExecStart with the failure prefix = %q", got["ExecStart"])
	}
	if got["ExecStartPre"] != "/usr/sbin/prep" {
		t.Errorf("ExecStartPre with the privilege prefix = %q", got["ExecStartPre"])
	}
	if got["ExecReload"] != "/bin/kill" {
		t.Errorf("ExecReload = %q, want the program the arguments are handed to", got["ExecReload"])
	}
}

func TestEnvironmentFileEdges(t *testing.T) {
	body := "LD_PRELOAD=/opt/hook.so\nPATH=/usr/local/bin:/usr/bin\nAPP_HOME=/opt/agent\n"
	edges := environmentEdges(body, rawEdge{trigger: "/etc/environment"})
	kinds := map[string]Kind{}
	for _, edge := range edges {
		kinds[edge.target] = edge.kind
	}
	if kinds["/opt/hook.so"] != Preload {
		t.Errorf("LD_PRELOAD edge = %+v", kinds["/opt/hook.so"])
	}
	if kinds["/opt/agent"] != Env {
		t.Errorf("file-valued assignment edge = %+v", kinds["/opt/agent"])
	}
	if _, ok := kinds["/usr/local/bin:/usr/bin"]; ok {
		t.Error("a PATH list is not a file edge")
	}
}

func TestCronEdges(t *testing.T) {
	body := "PATH=/usr/local/sbin:/usr/bin\n" +
		"17 *  * * * root /opt/agent --hourly\n" +
		"@reboot root /opt/boot-hook\n"
	edges := cronEdges(File{
		Path: "/etc/cron.d/agent", Surface: SurfaceCron, Dialect: CronDialect, Body: body,
	})
	var boot, hourly *rawEdge
	for index := range edges {
		edge := &edges[index]
		switch edge.target {
		case "/opt/boot-hook":
			boot = edge
		case "/opt/agent":
			hourly = edge
		}
	}
	if boot == nil || boot.phase != BootStaged {
		t.Errorf("@reboot edge = %+v, want boot-staged", boot)
	}
	if hourly == nil || hourly.subject != Account("root") {
		t.Errorf("system crontab subject = %+v, want the line's own user field", hourly)
	}
	// A user spool file's name is the account the lines run as.
	spool := cronEdges(File{
		Path: "/var/spool/cron/crontabs/alice", Surface: SurfaceCron, Dialect: CronDialect,
		Body: "30 4 * * * /home/alice/backup\n",
	})
	if len(spool) == 0 || spool[0].subject != Account("alice") {
		t.Errorf("spool subject = %+v", spool)
	}
	// Anacron's line has three leading fields; a bare run-parts is the
	// shell's PATH lookup and stays a dynamic edge — the decision is real,
	// only the target is unnamed until runtime. A builtin names no file at
	// all and stays quiet.
	bare := cronEdges(File{
		Path: "/etc/anacrontab", Surface: SurfaceCron, Dialect: CronDialect,
		Body: "7 5 daily run-parts /etc/cron.daily\n",
	})
	if len(bare) != 1 || !bare[0].dynamic || bare[0].target != "run-parts" {
		t.Errorf("a PATH-lookup command = %+v, want one dynamic edge naming run-parts", bare)
	}
	quiet := cronEdges(File{
		Path: "/etc/anacrontab", Surface: SurfaceCron, Dialect: CronDialect,
		Body: "7 5 daily test -x /usr/sbin/anacron\n",
	})
	if len(quiet) != 0 {
		t.Errorf("a builtin command stated an edge: %+v", quiet)
	}
	anacron := cronEdges(File{
		Path: "/etc/anacrontab", Surface: SurfaceCron, Dialect: CronDialect,
		Body: "7 5 daily /usr/sbin/run-parts /etc/cron.daily\n",
	})
	if len(anacron) == 0 || anacron[0].target != "/usr/sbin/run-parts" {
		t.Errorf("anacron edges = %+v", anacron)
	}
}

func TestWrapperGrammarMatchesOptionFields(t *testing.T) {
	// The option's command runs to the end of the line, colons included; the
	// keyword is a field's head word, so a daemon named in.tftspawnd never
	// matches.
	edges := wrapperCommands(File{
		Path: "/etc/hosts.allow", Surface: SurfaceSystem,
		Body: "in.tftspawnd: ALL\nsshd: ALL: spawn /bin/logger deny:%u\n",
	})
	if len(edges) != 1 || edges[0].target != "/bin/logger" || edges[0].mechanism != "spawn" {
		t.Fatalf("wrapper edges = %+v, want one spawn edge to /bin/logger", edges)
	}
	quoted := wrapperCommands(File{
		Path: "/etc/hosts.allow", Surface: SurfaceSystem,
		Body: `ALL: ALL: twist /bin/echo "denied: try again"`,
	})
	if len(quoted) != 1 || quoted[0].mechanism != "twist" || quoted[0].target != "/bin/echo" {
		t.Errorf("twist edges = %+v, want the echo with its quoted colon preserved", quoted)
	}
}

func TestPAMStackHasOneModulePerLine(t *testing.T) {
	// pam_exec's payload may end in .so; it is the exec's program, and the
	// old field loop minted a phantom module row (and a fake coverage gap)
	// from it.
	edges := pamEdges(File{
		Path: "/etc/pam.d/otp", Surface: SurfacePAM,
		Body: "auth required pam_exec.so /usr/sbin/otp-helper.so\nauth required pam_unix.so\n",
	}, corpusWithGlobs(nil))
	var exec bool
	for _, edge := range edges {
		if edge.mechanism == "pam_exec" && edge.target == "/usr/sbin/otp-helper.so" {
			exec = true
		}
		if edge.mechanism == "pam" {
			t.Errorf("phantom module edge: %+v", edge)
		}
	}
	if !exec {
		t.Errorf("pam_exec edges = %+v, want the payload as one exec", edges)
	}
}

// corpusWithGlobs builds a corpus whose filesystem answers the glob table the
// module resolution reads.
func corpusWithGlobs(globs map[string][]string) *Corpus {
	return NewCorpus(context.Background(), fakeFS{globs: globs}, nil, nil, allFiles)
}

func TestProxyCommandBareCommandStaysVisible(t *testing.T) {
	// A bare ProxyCommand is the PATH-hijack shape: the command must stay a
	// dynamic edge, the absolute one a real edge, and a builtin stays quiet
	// because the shell runs it itself.
	edges := sshConfigEdges(File{
		Path: "/etc/ssh/ssh_config", Surface: SurfaceSSH,
		Body: "Host *\n  ProxyCommand nc %h %p\n",
	})
	if len(edges) != 1 || !edges[0].dynamic || edges[0].target != "nc" {
		t.Errorf("bare proxycommand = %+v, want one dynamic edge naming nc", edges)
	}
	edges = sshConfigEdges(File{
		Path: "/etc/ssh/ssh_config", Surface: SurfaceSSH,
		Body: "Host *\n  ProxyCommand /usr/bin/nc %h %p\n",
	})
	if len(edges) != 1 || edges[0].dynamic || edges[0].target != "/usr/bin/nc" {
		t.Errorf("absolute proxycommand = %+v, want one edge to /usr/bin/nc", edges)
	}
	edges = sshConfigEdges(File{
		Path: "/etc/ssh/ssh_config", Surface: SurfaceSSH,
		Body: "Host *\n  ProxyCommand echo %h\n",
	})
	if len(edges) != 0 {
		t.Errorf("builtin proxycommand stated edges: %+v", edges)
	}
}

func TestUdevEdges(t *testing.T) {
	body := "ACTION==\"add\", RUN+=\"/opt/agent --plug\"\n" +
		"ACTION==\"add\", PROGRAM==\"/opt/discover\", NAME=%k\n" +
		"IMPORT{program}=\"/opt/probe --scan\"\n"
	edges := udevEdges(File{
		Path: "/etc/udev/rules.d/99-x.rules", Surface: SurfaceUdev, Dialect: UdevDialect, Body: body,
	})
	got := map[string]bool{}
	for _, edge := range edges {
		if edge.phase != Device || edge.subject.Class != AccountRoot {
			t.Errorf("udev edge %+v is not a root device edge", edge)
		}
		got[edge.target] = true
	}
	for _, want := range []string{"/opt/agent", "/opt/discover", "/opt/probe"} {
		if !got[want] {
			t.Errorf("udev edges missing %q: %+v", want, edges)
		}
	}
}

func TestDesktopEdges(t *testing.T) {
	body := "[Desktop Entry]\nType=Application\nExec=/opt/agent --gui\nTryExec=/opt/agent\n"
	edges := desktopEdges(File{
		Path: "/etc/xdg/autostart/agent.desktop", Surface: SurfaceXdg, Dialect: UnitDialect, Body: body,
	})
	if len(edges) < 2 {
		t.Fatalf("desktop edges = %+v", edges)
	}
	for _, edge := range edges {
		if edge.phase != Session || edge.mechanism != "Exec" && edge.mechanism != "TryExec" {
			t.Errorf("desktop edge = %+v", edge)
		}
		if edge.subject.Class != AccountLogin {
			t.Errorf("a system-wide autostart runs as the login account: %+v", edge)
		}
	}
}

func TestAuthorizedKeysForcedCommand(t *testing.T) {
	body := "ssh-ed25519 AAAA... comment\n" +
		"command=\"/opt/jail --user\",no-pty ssh-rsa BBBB...\n"
	edges := authorizedKeysEdges(File{
		Path: "/root/.ssh/authorized_keys", Surface: SurfaceSSH, Dialect: AuthorizedKeysDialect, Body: body,
	})
	if len(edges) == 0 || firstTarget(edges) != "/opt/jail" {
		t.Errorf("forced command edges = %+v", edges)
	}
	for _, edge := range edges {
		if edge.subject.Class != AccountRoot {
			t.Errorf("root's forced command runs as root: %+v", edge)
		}
	}
}

func TestModprobeEdges(t *testing.T) {
	body := "install karma_mod /opt/agent --load\n" +
		"blacklist other_mod\n"
	edges := modprobeEdges(File{
		Path: "/etc/modprobe.d/karma.conf", Surface: SurfaceModule, Dialect: ModprobeDialect, Body: body,
	})
	if len(edges) != 1 || firstTarget(edges) != "/opt/agent" {
		t.Errorf("install edges = %+v", edges)
	}
	if edges[0].mechanism != "install" || edges[0].phase != BootStaged {
		t.Errorf("install edge = %+v", edges[0])
	}
}

func TestSupervisorCommandWithAUser(t *testing.T) {
	body := "[program:agent]\ncommand=/opt/agent --serve\nuser=agent\n"
	edges := supervisorEdges(File{
		Path: "/etc/supervisor/conf.d/agent.conf", Surface: SurfaceSupervisor, Dialect: UnitDialect, Body: body,
	})
	if len(edges) == 0 || edges[0].subject != Account("agent") {
		t.Errorf("supervisor subject = %+v, want the section's user", edges)
	}
	if edges[0].phase != BootStaged || firstTarget(edges) != "/opt/agent" {
		t.Errorf("supervisor edge = %+v", edges[0])
	}
}

func TestAptHookEdges(t *testing.T) {
	body := "DPkg::Post-Invoke { \"/opt/agent --after\"; };\n"
	edges := aptEdges(File{
		Path: "/etc/apt/apt.conf.d/99-x", Surface: SurfaceApt, Dialect: AptDialect, Body: body,
	})
	if len(edges) == 0 || firstTarget(edges) != "/opt/agent" {
		t.Errorf("apt hook edges = %+v", edges)
	}
	for _, edge := range edges {
		if edge.subject.Class != AccountRoot || edge.phase != Scheduled {
			t.Errorf("an apt hook is root and scheduled: %+v", edge)
		}
	}
}

func TestLoaderPreloadEdges(t *testing.T) {
	body := "/opt/hook.so\nsoname-only.so # comment\n"
	edges := loaderEdges(File{
		Path: "/etc/ld.so.preload", Surface: SurfaceLoader, Dialect: LoaderDialect, Body: body,
	})
	if len(edges) != 2 {
		t.Fatalf("loader edges = %+v", edges)
	}
	if edges[0].target != "/opt/hook.so" || edges[0].kind != Preload || edges[0].subject.Class != AccountAll {
		t.Errorf("absolute preload edge = %+v", edges[0])
	}
	if !edges[1].dynamic {
		t.Errorf("a soname is dynamic until the search path answers: %+v", edges[1])
	}
}

func TestReferencesForTheProfile(t *testing.T) {
	refs := References("/opt/check.sh", "/opt/agent --serve\nsource /opt/vendor/env.sh\n")
	var targets []string
	for _, ref := range refs {
		targets = append(targets, ref.Target)
	}
	if len(refs) != 2 || targets[0] != "/opt/agent" || targets[1] != "/opt/vendor/env.sh" {
		t.Errorf("references = %+v", refs)
	}
	if refs[0].Kind != Exec || refs[1].Kind != Source {
		t.Errorf("reference kinds = %s %s", refs[0].Kind, refs[1].Kind)
	}
}
