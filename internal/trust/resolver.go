package trust

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// queryTimeout bounds one package-manager call. A live watcher annotates each
// new executable on the event path, and a package database that stopped
// answering must not hold the event loop.
const queryTimeout = 2 * time.Second

// Resolver answers package ownership from the distribution's own database: dpkg
// on Debian-family hosts, rpm on RedHat-family ones. Results are cached by path;
// an unowned path is a cache hit too, which is the common case for a dropped
// payload. A host with neither manager answers unknown, never unowned.
type Resolver struct {
	dpkg string
	rpm  string

	mu    sync.Mutex
	cache map[string]answer
}

type answer struct {
	pkg    string
	known  bool
	shared bool
}

// NewResolver looks up the package manager once. A missing manager is a valid
// resolver: every path answers unknown.
func NewResolver() *Resolver {
	r := &Resolver{cache: map[string]answer{}}
	if path, err := exec.LookPath("dpkg"); err == nil {
		r.dpkg = path
	}
	if path, err := exec.LookPath("rpm"); err == nil {
		r.rpm = path
	}
	return r
}

// Owned reports the package that owns path. known is false when no package
// manager answered (missing binary, timeout); an empty package with known true
// means the path is unowned.
func (r *Resolver) Owned(path string) (string, bool) {
	pkg, known, _ := r.OwnedShared(path)
	return pkg, known
}

// OwnedShared is Owned with the directory fact: a row that names several
// packages means the path is a shared directory, so its first name is a
// citation rather than the tree's owner.
func (r *Resolver) OwnedShared(path string) (string, bool, bool) {
	if r == nil || path == "" || (r.dpkg == "" && r.rpm == "") {
		return "", false, false
	}
	r.mu.Lock()
	cached, ok := r.cache[path]
	r.mu.Unlock()
	if ok {
		return cached.pkg, cached.known, cached.shared
	}
	result := r.query(path)
	r.mu.Lock()
	r.cache[path] = result
	r.mu.Unlock()
	return result.pkg, result.known, result.shared
}

// BatchSize bounds one package-manager argument list. A startup surface names
// a few dozen paths, but the resolver is also usable on a wider list and the
// argument list has a kernel limit.
const BatchSize = 100

// OwnedAll fills the cache for paths with as few package-manager calls as the
// manager allows. A manager that answers the whole batch — dpkg exits 1 for a
// path no package lists, rpm prints the files it owns — settles every path in
// the batch; a call that fails outright leaves them unknown.
func (r *Resolver) OwnedAll(paths []string) {
	if r == nil || (r.dpkg == "" && r.rpm == "") {
		return
	}
	missing := make([]string, 0, len(paths))
	seen := make(map[string]bool, len(paths))
	r.mu.Lock()
	for _, path := range paths {
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		if _, ok := r.cache[path]; !ok {
			missing = append(missing, path)
		}
	}
	r.mu.Unlock()
	for start := 0; start < len(missing); start += BatchSize {
		end := min(start+BatchSize, len(missing))
		r.queryBatch(missing[start:end])
	}
}

func (r *Resolver) queryBatch(paths []string) {
	var answers map[string]answer
	if r.dpkg != "" {
		answers = r.dpkgBatch(paths)
	} else {
		answers = r.rpmBatch(paths)
	}
	r.mu.Lock()
	for _, path := range paths {
		r.cache[path] = answers[path]
	}
	r.mu.Unlock()
}

// dpkgBatch runs one dpkg -S over the batch. dpkg exits 1 when any pattern
// names no file, which is an answer for the others and for the missing ones;
// only a timeout or an exec failure leaves the batch unknown. A row is
// `package: path` or `package:arch: path`, so the path follows the last
// separator.
func (r *Resolver) dpkgBatch(paths []string) map[string]answer {
	answers := make(map[string]answer, len(paths))
	out, err := run(r.dpkg, append([]string{"-S"}, paths...)...)
	if err != nil && !exitFailure(err) {
		for _, path := range paths {
			answers[path] = answer{}
		}
		return answers
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		cut := strings.LastIndex(line, ": ")
		if cut < 0 {
			continue
		}
		path := line[cut+2:]
		pkg := line[:cut]
		if strings.HasPrefix(pkg, "local diversion") {
			// The diversion target is a local file, not a package's.
			answers[path] = answer{known: true}
			continue
		}
		shared := false
		if comma := strings.IndexByte(pkg, ','); comma >= 0 {
			// A directory row lists every package with a file inside it; the
			// first name is enough for a citation.
			pkg = pkg[:comma]
			shared = true
		}
		pkg = strings.TrimSpace(pkg)
		if strings.Contains(pkg, ":") {
			// a multiarch row's `package:arch` spelling
			pkg, _, _ = strings.Cut(pkg, ":")
		}
		if _, seen := answers[path]; !seen {
			answers[path] = answer{pkg: pkg, known: true, shared: shared}
		}
	}
	for _, path := range paths {
		if _, ok := answers[path]; !ok {
			answers[path] = answer{known: true}
		}
	}
	return answers
}

// rpmBatch runs one rpm -qf over the batch with the file name in the query
// format, so every row names its own path. rpm exits non-zero for a file no
// package owns and keeps printing the rows it has; the files without a row are
// the unowned ones.
func (r *Resolver) rpmBatch(paths []string) map[string]answer {
	answers := make(map[string]answer, len(paths))
	args := append([]string{"-qf", "--qf", "%{NAME}\t%{FILENAMES}\n"}, paths...)
	out, err := run(r.rpm, args...)
	if err != nil && !exitFailure(err) {
		for _, path := range paths {
			answers[path] = answer{}
		}
		return answers
	}
	for _, line := range strings.Split(out, "\n") {
		name, path, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok || name == "" || path == "" {
			continue
		}
		if _, seen := answers[path]; !seen {
			answers[path] = answer{pkg: name, known: true}
		}
	}
	for _, path := range paths {
		if _, ok := answers[path]; !ok {
			answers[path] = answer{known: true}
		}
	}
	return answers
}

func (r *Resolver) query(path string) answer {
	if r.dpkg != "" {
		out, err := run(r.dpkg, "-S", path)
		if err != nil {
			// dpkg exits non-zero for a path no package lists, which is an
			// answer: the path is unowned. A timeout or an exec failure is
			// not, so those stay unknown.
			if exitFailure(err) {
				return answer{known: true}
			}
			return answer{}
		}
		return dpkgAnswer(out)
	}
	out, err := run(r.rpm, "-qf", path)
	if err != nil {
		if exitFailure(err) {
			return answer{known: true}
		}
		return answer{}
	}
	return answer{pkg: firstLine(out), known: true}
}

// dpkgRow reads the package out of a dpkg -S line: `package: path` for a normal
// row, `package:arch: path` for a multiarch one, so the path follows the last
// separator and the architecture suffix is dropped.
func dpkgAnswer(out string) answer {
	line := firstLine(out)
	if strings.HasPrefix(line, "local diversion") {
		return answer{known: true}
	}
	if cut := strings.LastIndex(line, ": "); cut >= 0 {
		line = line[:cut]
	}
	shared := false
	if comma := strings.IndexByte(line, ','); comma >= 0 {
		line = line[:comma]
		shared = true
	}
	line = strings.TrimSpace(line)
	if name, _, ok := strings.Cut(line, ":"); ok {
		line = name
	}
	return answer{pkg: line, known: true, shared: shared}
}

func firstLine(out string) string {
	line, _, _ := strings.Cut(out, "\n")
	return strings.TrimSpace(line)
}

// run returns the manager's stdout with its error: a batch manager prints the
// rows it did find and exits non-zero for the paths it did not, so the exit
// status classifies the answer while the stdout still carries it.
func run(binary string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	// The parsers match dpkg's own English words; a localized manager would
	// turn a diversion row into a package name.
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	return string(out), err
}

// exitFailure reports whether err is the command's own non-zero exit (an
// answer), rather than a timeout or an exec failure (no answer).
func exitFailure(err error) bool {
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return false
	}
	// A process killed by the context deadline is an ExitError whose process
	// did not exit; treating that as an answer would turn every path in the
	// batch into "unowned". Only a real non-zero exit is an answer.
	return exit.ProcessState != nil && exit.ProcessState.Exited()
}
