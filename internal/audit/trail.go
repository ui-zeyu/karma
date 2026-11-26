package audit

// The interactive trail: the files a person's session leaves behind. They are
// evidence, not verdicts. The collector reads a bounded set of them, the show
// section prints them, and the judge attaches the lines that name an object
// already under judgment as citations. A history file is not a finding by
// itself; it changes on every login.

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"karma/internal/localfs"
	"karma/internal/trust"
)

// TrailFile is one interactive artifact. Lines are the source lines the
// collector kept; Facts carries the same provenance every other object uses.
type TrailFile struct {
	Path      string      `json:"path"`
	Owner     int         `json:"owner"`
	Lines     []Quote     `json:"lines,omitempty"`
	Truncated bool        `json:"truncated,omitempty"`
	Facts     trust.Facts `json:"-"`
}

const (
	trailByteLimit = 512 << 10
	trailLineLimit = 4000
	trailTextLimit = 300
	// trailHomeLimit bounds a directory with thousands of home entries. The
	// named home directories that matter to the account graph are added
	// separately.
	trailHomeLimit = 200
)

// trailNames are the per-home files a session writes. A file that does not
// exist is skipped; an existing one joins the inventory even when empty.
var trailNames = []string{
	".bash_history",
	".zsh_history",
	".python_history",
	".viminfo",
	".lesshst",
	".mysql_history",
	".psql_history",
	".wget-hsts",
	".ssh/known_hosts",
}

// trailLogs are the authentication trails the system writes.
var trailLogs = []string{"/var/log/auth.log", "/var/log/secure"}

// trailPaths lists the trail files this host can carry: the root home, every
// home directory the collector can list, and the auth logs.
func trailPaths() []string {
	paths := append([]string(nil), trailLogs...)
	homes := []string{"/root"}
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, entry := range entries {
			if len(homes) >= trailHomeLimit {
				break
			}
			if entry.IsDir() {
				homes = append(homes, filepath.Join("/home", entry.Name()))
			}
		}
	}
	for _, home := range homes {
		for _, name := range trailNames {
			paths = append(paths, filepath.Join(home, name))
		}
	}
	sort.Strings(paths)
	return paths
}

// trailPathsFor adds the home directories the identity pass parsed, so an
// account whose home is outside /home still contributes its history.
func trailPathsFor(snapshot *Snapshot) []string {
	paths := trailPaths()
	if snapshot == nil {
		return paths
	}
	seen := make(map[string]bool, len(paths))
	for _, path := range paths {
		seen[path] = true
	}
	for _, account := range snapshot.Identity.Accounts {
		home := account.Home
		if home == "" || home == "/" || !filepath.IsAbs(home) {
			continue
		}
		// A home that is not a directory cannot carry trail files. Alpine's
		// sshd account names /dev/null, and asking for /dev/null/.bash_history
		// would answer ENOTDIR and mint a coverage line per trail name.
		if info, err := os.Stat(home); err != nil || !info.IsDir() {
			continue
		}
		for _, name := range trailNames {
			path := filepath.Join(home, name)
			if !seen[path] {
				seen[path] = true
				paths = append(paths, path)
			}
		}
	}
	sort.Strings(paths)
	return paths
}

// collectTrail reads the bounded trail set. It never follows a symlink and
// never blocks on a special file.
func collectTrail(ctx context.Context, snapshot *Snapshot) []string {
	var files []TrailFile
	var gaps []string
	for _, path := range trailPathsFor(snapshot) {
		if ctx.Err() != nil {
			break
		}
		if !snapshot.plan.Filter.touchesPath(path) {
			continue
		}
		info, err := os.Lstat(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				gaps = append(gaps, "trail unreadable: "+path+" ("+err.Error()+")")
			}
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		lines, truncated, err := readTrail(path)
		if err != nil {
			gaps = append(gaps, "trail unreadable: "+path+" ("+err.Error()+")")
			continue
		}
		files = append(files, TrailFile{Path: path, Lines: lines, Truncated: truncated})
	}
	if len(files) == 0 {
		return gaps
	}
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.Path)
	}
	snapshot.ensureFacts(paths)
	for index := range files {
		files[index].Facts = snapshot.Facts(files[index].Path)
		files[index].Owner = files[index].Facts.Owner
	}
	snapshot.Trail = files
	return gaps
}

// readTrail returns the non-empty source lines and whether the read stopped at
// a bound. The line numbers stay 1-based, so a citation points at the file.
func readTrail(path string) ([]Quote, bool, error) {
	file, err := localfs.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64<<10), 64<<10)
	var lines []Quote
	bytesRead := 0
	truncated := false
	for number := 1; scanner.Scan(); number++ {
		if len(lines) >= trailLineLimit || bytesRead >= trailByteLimit {
			truncated = true
			break
		}
		text := cleanTrailLine(scanner.Text())
		if text == "" {
			continue
		}
		bytesRead += len(scanner.Bytes())
		lines = append(lines, Quote{Path: path, Line: number, Text: truncate(text, trailTextLimit)})
	}
	if err := scanner.Err(); err != nil {
		return nil, false, err
	}
	return lines, truncated, nil
}

// cleanTrailLine keeps a history line printable: a control sequence in a
// shell history must not reach the terminal as a terminal command. Tabs
// become one column, the rest of the control range is dropped.
func cleanTrailLine(text string) string {
	var out strings.Builder
	for _, r := range text {
		switch {
		case r == '\t':
			out.WriteByte(' ')
		case r == 0x1b || r == 0x7f || r < 0x20:
			continue
		default:
			out.WriteRune(r)
		}
	}
	return strings.TrimSpace(out.String())
}

// trailRows is the TRAIL inventory: one row per artifact, the origin the same
// assessor gives every other object, and the last line a reader can start
// from.
func trailRows(view *View, options RenderOptions) []string {
	if len(view.Trail) == 0 {
		return nil
	}
	width := reportWidth(options.Width) - 4
	rows := []string{columnHeader([]string{"PATH", "OWNER", "ORIGIN", "LINES", "LAST"}, []int{44, 7, 10, 7})}
	for _, file := range view.Trail {
		origin := view.assessor.read(file.Facts, false).origin
		owner := "-"
		if file.Owner >= 0 {
			owner = strconv.Itoa(file.Owner)
		}
		count := strconv.Itoa(len(file.Lines))
		if file.Truncated {
			count += "+"
		}
		last := ""
		if len(file.Lines) > 0 {
			last = file.Lines[len(file.Lines)-1].Text
		}
		room := width - 76
		if room > 0 {
			last = truncate(last, room)
		} else {
			last = ""
		}
		rows = append(rows, columnRowHued(options.Color, []string{
			file.Path, owner, origin.String(), count,
		}, []int{44, 7, 10, 7}, []int{0, 0, originHue(origin), 0})+highlightTokens(last, mutedColor, options.Color))
	}
	return rows
}

// trailQuoteLimit caps the trail lines one finding cites. The source line
// that judged the object stays first; the history corroborates it.
const trailQuoteLimit = 3

// attachTrailEvidence cites the trail lines that name an object a finding
// already judges. It adds no finding of its own: a history line is evidence,
// not a verdict.
func attachTrailEvidence(trail []TrailFile, report *Report) {
	if len(trail) == 0 {
		return
	}
	paths := map[string][]int{}
	for index, finding := range report.Findings {
		if len(finding.Path) >= 6 {
			paths[finding.Path] = append(paths[finding.Path], index)
		}
	}
	if len(paths) == 0 {
		return
	}
	added := make(map[int]int, len(report.Findings))
	for _, file := range trail {
		for _, line := range file.Lines {
			for path, indices := range paths {
				if !containsPath(line.Text, path) {
					continue
				}
				for _, index := range indices {
					if added[index] >= trailQuoteLimit {
						continue
					}
					finding := &report.Findings[index]
					quote := Quote{Path: line.Path, Line: line.Line, Text: line.Text}
					if hasQuote(*finding, quote) {
						continue
					}
					finding.Quotes = append(finding.Quotes, quote)
					added[index]++
				}
			}
		}
	}
}

func hasQuote(finding Finding, quote Quote) bool {
	for _, existing := range finding.Quotes {
		if existing == quote {
			return true
		}
	}
	return false
}

// containsPath matches an absolute path at a token boundary, so /etc/pass does
// not match /etc/passwd and a URL does not match a directory.
func containsPath(text, path string) bool {
	at := 0
	for {
		index := strings.Index(text[at:], path)
		if index < 0 {
			return false
		}
		index += at
		before := index == 0 || !pathByte(text[index-1])
		end := index + len(path)
		after := end == len(text) || !pathByte(text[end])
		if before && after {
			return true
		}
		at = index + 1
	}
}

func pathByte(c byte) bool {
	return c == '/' || c == '.' || c == '-' || c == '_' ||
		c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
