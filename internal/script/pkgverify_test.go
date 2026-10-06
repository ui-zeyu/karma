// The package-verify body is one contract with two implementations: the Go
// renderer the local channel uses, and the awk program the ssh and ttyd
// channels run. These tests pin the shape, then run the awk over a marked
// stream built the way the shell builds it and compare the two bodies line for
// line, so a grouping, threshold or title change cannot land on one side alone.

package script

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// noFacts classifies nothing: a test's fixture is not on this host.
func noFacts(string) VerifyFacts { return VerifyFacts{} }

// factsOf answers the classification from a table, the way the local channel
// answers it from the filesystem.
func factsOf(table map[string]VerifyFacts) func(string) VerifyFacts {
	return func(path string) VerifyFacts { return table[path] }
}

// detailOf renders the forensics from a table of pre-built bodies, the way
// localfs renders them from file(1)'s and ls -l's answers.
func detailOf(files, ls string) func([]string) (string, string) {
	return func([]string) (string, string) { return files, ls }
}

// marked builds the piped stream PkgVerifyScript builds: every verifier line
// tagged V, every `path: type` line tagged F, every ls -l row tagged L.
func marked(sections ...[]string) string {
	tags := []string{"V", "F", "L"}
	var b strings.Builder
	for i, lines := range sections {
		tag := tags[i]
		for _, line := range lines {
			b.WriteString(tag + " " + line + "\n")
		}
	}
	return b.String()
}

// runsAwk runs the pipeline's awk program over a marked stream and returns its
// body. havefile mirrors the shell's `command -v file` test.
func runsAwk(t *testing.T, stream string, havefile bool) string {
	t.Helper()
	if _, err := exec.LookPath("awk"); err != nil {
		t.Skip("no awk on this host")
	}
	cmd := exec.Command("awk", "-v", "havefile="+map[bool]string{true: "1", false: "0"}[havefile], pkgVerifyAwk())
	cmd.Stdin = strings.NewReader(stream)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("the awk program failed: %v (output %q)", err, out)
	}
	return string(out)
}

// A verified-clean host prints nothing: the body is empty rather than a header.
func TestPkgVerifyBodyEmptyWithoutRows(t *testing.T) {
	if got := PkgVerifyBody("", noFacts, nil); got != "" {
		t.Errorf("an empty verification rendered %q, want nothing", got)
	}
}

// The rows of the files that can be a finding are named one by one, in the
// verifier's own order, with their type and attributes after them.
func TestPkgVerifyBodyNamesKeyFiles(t *testing.T) {
	verify := "??5??????   /usr/lib/x/libevil.so\n"
	facts := map[string]VerifyFacts{
		"/usr/lib/x/libevil.so": {Key: true},
	}
	files := "/usr/lib/x/libevil.so: ELF 64-bit LSB shared object\n"
	ls := "-rw-r--r-- 1 root root 8600 May 18 07:20 /usr/lib/x/libevil.so\n"
	got := PkgVerifyBody(verify, factsOf(facts), detailOf(files, ls))
	want := "== executables, libraries and conffiles\n" +
		"??5??????   /usr/lib/x/libevil.so\n" +
		"== file\n" + files +
		"== ls\n" + ls
	if got != want {
		t.Errorf("the key files rendered as\n%q\nwant\n%q", got, want)
	}
}

// A named row whose file is gone carries the mark: neither dpkg's nor rpm's
// flag field tells a deleted file from a modified one, and on a small
// directory that row is the only evidence there is.
func TestPkgVerifyBodyMarksMissingFiles(t *testing.T) {
	verify := "??5??????   /opt/x/a.conf\n??5??????   /opt/x/b.conf\n"
	facts := map[string]VerifyFacts{"/opt/x/a.conf": {Missing: true}}
	got := PkgVerifyBody(verify, factsOf(facts), nil)
	want := "== other changed files (grouped by directory)\n" +
		"??5??????   /opt/x/a.conf (missing)\n??5??????   /opt/x/b.conf\n"
	if got != want {
		t.Errorf("a named missing file rendered as\n%q\nwant\n%q", got, want)
	}
}

// A conffile is a key file even though no type finds it: the administrator's
// edit and the shipped default are what the analyst compares.
func TestPkgVerifyBodyNamesConffiles(t *testing.T) {
	verify := "??5?????? c /etc/ssh/sshd_config\n"
	got := PkgVerifyBody(verify, noFacts, nil)
	want := "== executables, libraries and conffiles\n??5?????? c /etc/ssh/sshd_config\n"
	if got != want {
		t.Errorf("a changed conffile rendered as %q, want %q", got, want)
	}
}

// A directory that holds few rows keeps them, names and all: a divergence of
// three text files is evidence, not noise.
func TestPkgVerifyBodyListsSmallDirectories(t *testing.T) {
	verify := "??5??????   /opt/x/a.conf\n??5??????   /opt/x/b.conf\n??5??????   /opt/y/c.conf\n"
	got := PkgVerifyBody(verify, noFacts, nil)
	want := "== other changed files (grouped by directory)\n" +
		"??5??????   /opt/x/a.conf\n??5??????   /opt/x/b.conf\n??5??????   /opt/y/c.conf\n"
	if got != want {
		t.Errorf("small directories rendered as\n%q\nwant\n%q", got, want)
	}
}

// A directory with more rows than the listing threshold is counted once, at
// the deepest ancestor that carries a mass, with how many of its files are
// gone rather than modified.
func TestPkgVerifyBodyCountsBigDirectories(t *testing.T) {
	var lines []string
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		lines = append(lines, "??5??????   /usr/share/doc/"+name)
	}
	facts := map[string]VerifyFacts{"/usr/share/doc/a": {Missing: true}}
	got := PkgVerifyBody(strings.Join(lines, "\n")+"\n", factsOf(facts), nil)
	want := "== other changed files (grouped by directory)\n" +
		"??5??????   /usr/share/doc/  5 files differ, 1 missing\n"
	if got != want {
		t.Errorf("a big directory rendered as\n%q\nwant\n%q", got, want)
	}
}

// A lone file below the mass is counted with its ancestor rather than named
// after its own directory, which would only add a row to the wall.
func TestPkgVerifyBodyRollsSmallDirectoriesUp(t *testing.T) {
	var lines []string
	for i := 0; i < 25; i++ {
		lines = append(lines, "??5??????   /usr/share/doc/pkg"+strconv.Itoa(i)+"/readme")
	}
	lines = append(lines, "??5??????   /usr/share/doc/tiny/readme")
	got := PkgVerifyBody(strings.Join(lines, "\n")+"\n", noFacts, nil)
	want := "== other changed files (grouped by directory)\n" +
		"??5??????   /usr/share/doc/  26 files differ\n"
	if got != want {
		t.Errorf("a rolled-up directory rendered as\n%q\nwant\n%q", got, want)
	}
}

// The awk program is the remote half of the same body: over the same rows and
// the same facts it must print the same text, key files, missing marks and
// counts alike. The stream is the one the shell builds, so the tags, file(1)'s
// type words and the ls -l rows are all exercised.
//
// The fixture's rows arrive in an order that is not the sorted one, and the
// expected body comes from the Go renderer over the same order: the `== file`
// section keeps the order its producer printed, so a sort added to either
// implementation alone fails here. The other half of that contract — the local
// producer not sorting what it is handed — is pinned by localfs.TestFileRows.
func TestPkgVerifyAwkMatchesBody(t *testing.T) {
	verify := []string{
		"??5??????   /usr/bin/sshd",
		"??5?????? c /etc/ssh/sshd_config",
		"missing   c /etc/default/grub.d/kdump-tools.cfg",
		"??5??????   /usr/lib/x/libevil.so",
		"??5??????   /usr/share/doc/a",
		"??5??????   /usr/share/doc/b",
		"??5??????   /usr/share/doc/c",
		"??5??????   /usr/share/doc/d",
		"??5??????   /usr/share/doc/e",
	}
	types := []string{
		"/usr/bin/sshd: ELF 64-bit LSB executable",
		"/etc/ssh/sshd_config: ASCII text",
		"/etc/default/grub.d/kdump-tools.cfg: cannot open `/etc/default/grub.d/kdump-tools.cfg' (No such file or directory)",
		"/usr/lib/x/libevil.so: cannot open `/usr/lib/x/libevil.so' (No such file or directory)",
		"/usr/share/doc/a: cannot open `/usr/share/doc/a' (No such file or directory)",
		"/usr/share/doc/b: cannot open `/usr/share/doc/b' (No such file or directory)",
		"/usr/share/doc/c: cannot open `/usr/share/doc/c' (No such file or directory)",
		"/usr/share/doc/d: cannot open `/usr/share/doc/d' (No such file or directory)",
		"/usr/share/doc/e: cannot open `/usr/share/doc/e' (No such file or directory)",
	}
	modes := []string{
		"-rwxr-xr-x 1 root root 8600 May 18 07:20 /usr/bin/sshd",
		"-rw-r--r-- 1 root root 358 May 16 15:05 /etc/ssh/sshd_config",
	}
	// Key and missing are mutually exclusive in both implementations: a path
	// that cannot be read has no type to classify.
	facts := map[string]VerifyFacts{
		"/usr/bin/sshd":                       {Key: true},
		"/etc/ssh/sshd_config":                {Key: true},
		"/etc/default/grub.d/kdump-tools.cfg": {Missing: true},
		"/usr/lib/x/libevil.so":               {Missing: true},
		"/usr/share/doc/a":                    {Missing: true},
		"/usr/share/doc/b":                    {Missing: true},
		"/usr/share/doc/c":                    {Missing: true},
		"/usr/share/doc/d":                    {Missing: true},
		"/usr/share/doc/e":                    {Missing: true},
	}
	// The shell squeezes file(1)'s aligned columns; the missing rows are left
	// out the way localfs.FileRows leaves them out.
	files := "/usr/bin/sshd: ELF 64-bit LSB executable\n" +
		"/etc/ssh/sshd_config: ASCII text\n"
	ls := strings.Join(modes, "\n") + "\n"
	want := PkgVerifyBody(strings.Join(verify, "\n")+"\n", factsOf(facts), detailOf(files, ls))
	got := runsAwk(t, marked(verify, types, modes), true)
	if got != want {
		t.Errorf("the awk pipeline rendered\n%q\nwant\n%q", got, want)
	}
}

// A host without file(1) still gets the grouping and the key executables from
// the attributes, and no missing mark: an unknowable "gone" must not be
// guessed at.
func TestPkgVerifyAwkWithoutFile(t *testing.T) {
	verify := []string{
		"??5??????   /usr/bin/tool",
		"??5??????   /usr/share/doc/a",
		"??5??????   /usr/share/doc/b",
		"??5??????   /usr/share/doc/c",
		"??5??????   /usr/share/doc/d",
	}
	modes := []string{"-rwxr-xr-x 1 root root 8600 May 18 07:20 /usr/bin/tool"}
	want := "== executables, libraries and conffiles\n" +
		"??5??????   /usr/bin/tool\n" +
		"== ls\n" + modes[0] + "\n" +
		"== other changed files (grouped by directory)\n" +
		"??5??????   /usr/share/doc/  4 files\n"
	got := runsAwk(t, marked(verify, nil, modes), false)
	if got != want {
		t.Errorf("the awk pipeline without file(1) rendered\n%q\nwant\n%q", got, want)
	}
}

// file(1) pads its type column when it reads a long name list, which is how
// the ssh and ttyd rows arrive; the body squeezes the run of spaces back to
// the single separator the local channel's in-process rows carry. The padded
// row still classifies: the type word is what makes a file a key one.
func TestPkgVerifyAwkSqueezesFilePadding(t *testing.T) {
	verify := []string{"??5??????   /usr/lib/x/libevil.so"}
	types := []string{"/usr/lib/x/libevil.so:                      ELF 64-bit LSB shared object"}
	want := "== executables, libraries and conffiles\n" +
		"??5??????   /usr/lib/x/libevil.so\n" +
		"== file\n/usr/lib/x/libevil.so: ELF 64-bit LSB shared object\n"
	if got := runsAwk(t, marked(verify, types), true); got != want {
		t.Errorf("the padded type row rendered as\n%q\nwant\n%q", got, want)
	}
}
