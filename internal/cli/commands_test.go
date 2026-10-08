package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"karma/internal/model"
	"karma/internal/session"
)

func newSSHFlags() *pflag.FlagSet {
	flags := pflag.NewFlagSet("ssh", pflag.ContinueOnError)
	sshFlags(flags)
	return flags
}

func TestBuildSSHTransport(t *testing.T) {
	key := filepath.Join(t.TempDir(), "id_test")
	if err := os.WriteFile(key, []byte("dummy"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("defaults accept any host key", func(t *testing.T) {
		transport, err := buildSSHTransport(newSSHFlags(), "root@10.0.0.8")
		if err != nil {
			t.Fatal(err)
		}
		ssh := transport.(*session.SSHTransport)
		if ssh.HostKey != session.HostKeyNo || ssh.Port != 0 || ssh.Password != "" {
			t.Fatalf("wrong defaults: %+v", ssh)
		}
	})

	t.Run("the three host key modes", func(t *testing.T) {
		for raw, want := range map[string]session.HostKeyMode{
			"no":         session.HostKeyNo,
			"yes":        session.HostKeyYes,
			"ACCEPT-NEW": session.HostKeyAcceptNew,
		} {
			flags := newSSHFlags()
			if err := flags.Set("ssh-option", "StrictHostKeyChecking="+raw); err != nil {
				t.Fatal(err)
			}
			transport, err := buildSSHTransport(flags, "root@10.0.0.8")
			if err != nil {
				t.Fatalf("%s: %v", raw, err)
			}
			if got := transport.(*session.SSHTransport).HostKey; got != want {
				t.Fatalf("StrictHostKeyChecking=%s mapped to %v, want %v", raw, got, want)
			}
		}
	})

	t.Run("unknown and repeated -o", func(t *testing.T) {
		flags := newSSHFlags()
		flags.Set("ssh-option", "Level=none")
		if _, err := buildSSHTransport(flags, "root@10.0.0.8"); err == nil {
			t.Fatal("an unknown -o should fail")
		}
		flags = newSSHFlags()
		flags.Set("ssh-option", "StrictHostKeyChecking=no")
		flags.Set("ssh-option", "StrictHostKeyChecking=yes")
		if _, err := buildSSHTransport(flags, "root@10.0.0.8"); err == nil {
			t.Fatal("repeating StrictHostKeyChecking should fail")
		}
	})

	t.Run("port out of range", func(t *testing.T) {
		for _, port := range []string{"-3", "70000"} {
			flags := newSSHFlags()
			flags.Set("port", port)
			if _, err := buildSSHTransport(flags, "root@10.0.0.8"); err == nil {
				t.Fatalf("port %s should fail", port)
			}
		}
	})

	t.Run("missing identity file", func(t *testing.T) {
		flags := newSSHFlags()
		flags.Set("identity", "/nonexistent/karma-test-key")
		if _, err := buildSSHTransport(flags, "root@10.0.0.8"); err == nil {
			t.Fatal("a missing identity file should fail")
		}
	})

	t.Run("password flag value", func(t *testing.T) {
		flags := newSSHFlags()
		flags.Set("password", "clipw")
		transport, err := buildSSHTransport(flags, "root@10.0.0.8")
		if err != nil {
			t.Fatal(err)
		}
		if got := transport.(*session.SSHTransport).Password; got != "clipw" {
			t.Fatalf("password = %q", got)
		}
	})

	t.Run("non-URI target without a colon", func(t *testing.T) {
		if _, err := buildSSHTransport(newSSHFlags(), "10.0.0.8:2222"); err == nil {
			t.Fatal("the short form with a port should fail and point at the URI form")
		}
	})
}

func TestRunOptions(t *testing.T) {
	newRunFlags := func() *pflag.FlagSet {
		flags := pflag.NewFlagSet("run", pflag.ContinueOnError)
		runFlags(flags)
		return flags
	}

	options, err := runOptions(newRunFlags(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if options.Concurrency != model.DefaultConcurrency ||
		options.Timeout != model.DefaultTimeout ||
		options.MaxLines != model.DefaultMaxLines ||
		options.MinSeverity != model.FloorAll {
		t.Fatalf("wrong defaults: %+v", options)
	}

	for name, value := range map[string]string{
		"concurrency": "0", "timeout": "0.4", "max-lines": "0", "min-severity": "severe",
	} {
		flags := newRunFlags()
		flags.Set(name, value)
		if _, err := runOptions(flags, nil); err == nil {
			t.Fatalf("%s=%s should fail", name, value)
		}
	}

	// The severity floor takes the level vocabulary plus the word that keeps the
	// whole report; each level name is the floor above it.
	for word, want := range map[string]model.SeverityFloor{
		"all":      model.FloorAll,
		"critical": model.FloorAbove(model.Critical),
		"high":     model.FloorAbove(model.High),
		"medium":   model.FloorAbove(model.Medium),
		"low":      model.FloorAbove(model.Low),
		"info":     model.FloorAbove(model.Info),
		"benign":   model.FloorAbove(model.Benign),
	} {
		flags := newRunFlags()
		flags.Set("min-severity", word)
		options, err := runOptions(flags, nil)
		if err != nil {
			t.Fatalf("min-severity=%s: %v", word, err)
		}
		if options.MinSeverity != want {
			t.Fatalf("min-severity=%s mapped to %v, want %v", word, options.MinSeverity, want)
		}
	}

	flags := newRunFlags()
	flags.Set("timeout", "1.5")
	options, err = runOptions(flags, nil)
	if err != nil {
		t.Fatal(err)
	}
	if options.Timeout != 1500*time.Millisecond {
		t.Fatalf("values mapped wrongly: %+v", options)
	}
}

// version is a subcommand: it prints "karma <version>" on stdout and nothing else.
func TestVersionSubcommand(t *testing.T) {
	root := newRootCmd("9.9.9")
	root.SetArgs([]string{"version"})
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	if err := root.Execute(); err != nil {
		t.Fatalf("version should succeed: %v", err)
	}
	if got := out.String(); got != "karma 9.9.9\n" {
		t.Fatalf("version output: %q", got)
	}
	if errOut.Len() != 0 {
		t.Fatalf("version should stay off stderr: %q", errOut.String())
	}
}

// --version is cobra's root flag: it prints the same line the subcommand prints.
func TestVersionFlag(t *testing.T) {
	root := newRootCmd("9.9.9")
	root.SetArgs([]string{"--version"})
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	if err := root.Execute(); err != nil {
		t.Fatalf("--version should succeed: %v", err)
	}
	if got := out.String(); got != "karma 9.9.9\n" {
		t.Fatalf("--version output: %q", got)
	}
	if errOut.Len() != 0 {
		t.Fatalf("--version should stay off stderr: %q", errOut.String())
	}
}

// The catalog is drawn on the command's own stream, like every other mode: a
// caller that captured the stream gets it, and nothing is written to the
// process's own handle behind the caller's back.
func TestListDrawsOnTheCommandsStream(t *testing.T) {
	root := newRootCmd("test")
	root.SetArgs([]string{"list", "uptime"})
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	if err := root.Execute(); err != nil {
		t.Fatalf("list should succeed: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "uptime") {
		t.Fatalf("the catalog should be on the command's out stream: %q", got)
	}
	if errOut.Len() != 0 {
		t.Fatalf("list should stay off stderr: %q", errOut.String())
	}
}

// reportError's two shapes: a usage error appends the usage block and returns 0
// (a typo is not a failed run, so the shell's status stays quiet), a coded error
// returns its own code, and anything else returns 0 with the message only.
func TestReportError(t *testing.T) {
	root := newRootCmd("test")
	usage := usagef(root, "unknown command %q", "zzz")
	var buf bytes.Buffer
	if code := reportError(&buf, usage); code != 0 {
		t.Fatalf("a usage error should return 0, got %d", code)
	}
	if got := buf.String(); !strings.HasPrefix(got, "karma: unknown command \"zzz\"\n") ||
		!strings.Contains(got, "USAGE") || !strings.Contains(got, "COMMANDS") {
		t.Fatalf("a usage error should print the message then the usage: %q", got)
	}

	buf.Reset()
	if code := reportError(&buf, failf(2, "connection failed: %v", "x")); code != 2 {
		t.Fatalf("a coded error should return its code, got %d", code)
	}
	if got := buf.String(); got != "karma: connection failed: x\n" {
		t.Fatalf("a coded error prints one line: %q", got)
	}

	buf.Reset()
	if code := reportError(&buf, errors.New("internal blow-up")); code != 0 {
		t.Fatalf("an explained mistake should return 0, got %d", code)
	}
	if got := buf.String(); got != "karma: internal blow-up\n" {
		t.Fatalf("an explained mistake prints one line: %q", got)
	}
}

// Command-line usage mistakes: an English message with a usage block where it
// applies, and a close-command hint for a recognizable typo. The exit code stays
// 0 so a typo never looks like a failed run.
func TestCommandLineErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		wantErr []string
	}{
		{"unknown command gets a suggestion", []string{"lst"}, []string{`unknown command "lst"`, "Did you mean: list"}},
		{"a typo only gets the closest", []string{"locl"}, []string{"Did you mean: local"}},
		{"a mode that lives on a channel command gets its placement", []string{"mtime", "/tmp"}, []string{`unknown command "mtime"`, "karma local mtime"}},
		{"unknown flag", []string{"local", "--typo"}, []string{"unknown flag --typo", "FLAGS"}},
		{"unknown shorthand flag", []string{"local", "-x"}, []string{"unknown shorthand flag -x"}},
		{"flag needs a value", []string{"local", "--timeout"}, []string{"flag --timeout needs a value"}},
		{"invalid flag value", []string{"local", "--timeout", "abc"}, []string{"invalid value abc for flag --timeout"}},
		{"ssh needs a target", []string{"ssh"}, []string{"ssh needs a target", "USAGE"}},
		{"value out of range", []string{"local", "--concurrency", "0"}, []string{"--concurrency must be >= 1"}},
		{"misspelled selector", []string{"list", "sysem"}, []string{`unknown selector "sysem"`, "system"}},
		{"help with an unknown target", []string{"help", "zzz"}, []string{`unknown command "zzz"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := newRootCmd("test")
			root.SetArgs(tc.args)
			var out, errOut bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&errOut)
			err := root.Execute()
			if err == nil {
				t.Fatalf("should fail, stdout: %q", out.String())
			}
			var reported bytes.Buffer
			if code := reportError(&reported, err); code != 0 {
				t.Fatalf("a usage/input mistake should return 0, got %d (%v)", code, err)
			}
			got := reported.String()
			for _, want := range tc.wantErr {
				if !strings.Contains(got, want) {
					t.Fatalf("missing %q: %q", want, got)
				}
			}
			if out.Len() != 0 {
				t.Fatalf("an error must not go to stdout: %q", out.String())
			}
		})
	}
}

// A missing argument that is not a usage error (mtime directories) takes the
// other branch on Windows.
func TestMtimeNeedsDirs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("on Windows mtime reports the unsupported platform directly")
	}
	root := newRootCmd("test")
	root.SetArgs([]string{"local", "mtime"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "mtime needs at least one directory") {
		t.Fatalf("a missing directory should fail: %v", err)
	}
	var reported bytes.Buffer
	if code := reportError(&reported, err); code != 0 {
		t.Fatalf("a missing directory should return 0, got %d", code)
	}
}

// The built-in readers under local: cat prints the files' bytes in order, ls
// the collection's bare ls-l rows (one section per path when there are
// several), neither runs the host's binaries, and neither word shadows a
// selector — collection arguments still reach the run.
func TestLocalCatAndLs(t *testing.T) {
	dir := t.TempDir()
	one := filepath.Join(dir, "one.txt")
	two := filepath.Join(dir, "two.txt")
	if err := os.WriteFile(one, []byte("line1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(two, []byte("line2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	run := func(t *testing.T, args ...string) string {
		t.Helper()
		root := newRootCmd("test")
		root.SetArgs(args)
		var out, errOut bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&errOut)
		if err := root.Execute(); err != nil {
			t.Fatalf("%v should succeed: %v", args, err)
		}
		return out.String()
	}

	// cat prints the bytes exactly, several files concatenated — no collection
	// header, so the output pipes and hashes like cat's own
	if got := run(t, "local", "cat", one, two); got != "line1\nline2\n" {
		t.Fatalf("cat printed %q", got)
	}
	// ls prints bare ls-l rows over the full paths; several paths get a
	// section header each
	rows := run(t, "local", "ls", dir, dir)
	if !strings.Contains(rows, "== "+dir+"\n") || strings.Count(rows, "== ") != 2 {
		t.Fatalf("each path should head a section: %q", rows)
	}
	if !strings.Contains(rows, " "+one+"\n") || strings.Contains(rows, "\t") {
		t.Fatalf("ls rows wrong: %q", rows)
	}
	// a file operand prints its own row
	if got := run(t, "local", "ls", one); !strings.HasPrefix(got, "-rw") {
		t.Fatalf("a file operand should print its own row: %q", got)
	}
	// with no path the current directory is listed, entries named the way ls
	// itself names them
	t.Chdir(dir)
	if got := run(t, "local", "ls"); !strings.Contains(got, " one.txt\n") {
		t.Fatalf("the default should list the current directory: %q", got)
	}

	// a read that failed exits 1, the status the replaced tools use; a usage
	// mistake stays at 0 so a typo never looks like a failed read
	for _, tc := range []struct {
		name     string
		args     []string
		wantErr  string
		wantCode int
	}{
		{"cat a missing file", []string{"local", "cat", filepath.Join(dir, "none")}, ": no such file or directory", 1},
		{"cat a directory", []string{"local", "cat", dir}, ": is a directory", 1},
		{"ls a missing path", []string{"local", "ls", filepath.Join(dir, "none")}, ": no such file or directory", 1},
		{"cat needs a word", []string{"local", "cat"}, "cat needs at least one file", 0},
		{"cat at the root points under local", []string{"cat", "/etc/passwd"}, `"karma local cat FILE..."`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := newRootCmd("test")
			root.SetArgs(tc.args)
			root.SetOut(&bytes.Buffer{})
			root.SetErr(&bytes.Buffer{})
			err := root.Execute()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want %q in the failure, got %v", tc.wantErr, err)
			}
			var reported bytes.Buffer
			if code := reportError(&reported, err); code != tc.wantCode {
				t.Fatalf("want exit code %d, got %d (%v)", tc.wantCode, code, err)
			}
		})
	}

	// a failed operand is reported after the rest have printed: the rows of
	// the good path stay on stdout, the failure goes to the caller with the
	// status of a failed read
	root := newRootCmd("test")
	root.SetArgs([]string{"local", "ls", filepath.Join(dir, "none"), dir})
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "no such file or directory") {
		t.Fatalf("the failed path should be reported: %v", err)
	}
	if !strings.Contains(out.String(), " "+one+"\n") {
		t.Fatalf("the surviving path should have printed: %q", out.String())
	}
	if code := reportError(&bytes.Buffer{}, err); code != 1 {
		t.Fatalf("a failed operand should exit 1, got %d", code)
	}

	// a selector word is not a subcommand: it still reaches the run and fails
	// on its own vocabulary
	root = newRootCmd("test")
	root.SetArgs([]string{"local", "zzz"})
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), `unknown selector "zzz"`) {
		t.Fatalf("selectors should still route to the run: %v", err)
	}
}

// The usage and help text is cobra's own English, without the completion
// boilerplate.
func TestUsageAndHelpAreEnglish(t *testing.T) {
	root := newRootCmd("test")
	root.SetArgs([]string{"--help"})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{"USAGE", "COMMANDS", "FLAGS", "Show the usage of any command"} {
		if !strings.Contains(got, want) {
			t.Fatalf("the help is missing %q: %q", want, got)
		}
	}
	if strings.Contains(got, "completion") {
		t.Fatalf("the help must not advertise completions: %q", got)
	}
}

// The help screen is the report's first panel: the command path as the
// level-one band with the byline on its right edge, the build's version as the
// level-two head underneath, and the command's description inside the same
// rail — the skeleton and the evidence read as one language.
func TestHelpWearsTheFirstPanelsShape(t *testing.T) {
	root := newRootCmd("9.9.9")
	root.SetArgs([]string{"local", "--help"})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	lines := strings.Split(got, "\n")
	if !strings.HasPrefix(lines[0], " KARMA LOCAL") || !strings.Contains(lines[0], "yuyy") {
		t.Fatalf("the help opens with the command band and its byline: %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "▌ 9.9.9") {
		t.Fatalf("the panel head under the band carries the version: %q", lines[1])
	}
	described := false
	for _, line := range lines {
		if !strings.Contains(line, "Collect read-only evidence from the local host.") {
			continue
		}
		if !strings.HasPrefix(line, "▌") {
			t.Fatalf("the description belongs inside the rail: %q", line)
		}
		described = true
	}
	if !described {
		t.Fatalf("the help should carry the command's own description: %q", got)
	}
}

// flagErrorText recognizes pflag's four error shapes; an unknown shape keeps its
// original text.
func TestFlagErrorText(t *testing.T) {
	flags := pflag.NewFlagSet("t", pflag.ContinueOnError)
	flags.IntP("port", "p", 0, "")
	flags.Float64("timeout", 0, "")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--typo"}, "unknown flag --typo"},
		{[]string{"-x"}, "unknown shorthand flag -x"},
		{[]string{"--timeout"}, "flag --timeout needs a value"},
		{[]string{"--timeout", "abc"}, "invalid value abc for flag --timeout"},
	} {
		err := flags.Parse(tc.args)
		if err == nil {
			t.Fatalf("%v should fail", tc.args)
		}
		if got := flagErrorText(err); got != tc.want {
			t.Fatalf("%v: got %q, want %q", tc.args, got, tc.want)
		}
	}
	if got := flagErrorText(errors.New("some other error")); got != "some other error" {
		t.Fatalf("an unknown shape should keep its original text: %q", got)
	}
}
