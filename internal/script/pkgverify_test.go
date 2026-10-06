// The package-verify body is one contract with two implementations: the Go
// renderer the local channel uses, and the awk program the ssh and ttyd
// channels run. These tests pin the shape, then run the awk over a marked
// stream built the way the shell builds it and compare the two bodies line for
// line, so a grouping, threshold or title change cannot land on one side alone.

package script

import (
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
