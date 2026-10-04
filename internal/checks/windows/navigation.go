// navigation browsing and search: WordWheelQuery, TypedPaths, Shellbags.
//
// Shellbags are parsed by shell item structure (internal/checks/windows/shellitem.go):
// the key tree is joined into full paths, yielding a timestamped browsing timeline; unrecognized
// entries fall back to sliding-window string extraction.

package windows

import (
	"cmp"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/samber/lo"

	"karma/internal/define"
	"karma/internal/model"
	"karma/internal/regout"
)

const wordwheelKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`
const typedpathsKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`

var wordwheelKeys = []RegKey{
	{Path: wordwheelKey, Recurse: true, Label: "reg-direct"},
}
var typedpathsKeys = []RegKey{
	{Path: typedpathsKey, Label: "reg-direct"},
}

// shellbagKeys: UsrClass.dat (Software\Classes) is where Win10+ actually stores BagMRU;
// the NTUSER.DAT copy exists on some systems but is often empty, so query both and section each.
var shellbagKeys = []RegKey{
	{Path: `HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`, Recurse: true, Label: "usrclass"},
	{Path: `HKCU\Software\Microsoft\Windows\Shell\BagMRU`, Recurse: true, Label: "ntuser"},
}

const searchSensitive = `(?i)(?:password|passwd|pwd|secret|credential|salary|\.kdbx|\.ppk|id_rsa` +
	`|密码|口令|凭据|工资|薪资)`

// nonlocalPath: an FTP URL or a UNC share (\\host\) appearing in a search term or
// a browsed folder -- the shape both navigation checks look for.
const nonlocalPath = `(?i)(?:ftp://|\\\\[A-Za-z0-9_.-]+\\)`

var guidOnly = regexp.MustCompile(`^\{[0-9A-Fa-f-]{36}\}$`)

// shellbagNormalize parses BagMRU values by shell item structure into a browsing timeline: the key
// path (the index chain after BagMRU) is the parent chain, used to join full paths. Each line is
// `time  path`, where time is the access time (last opened via Explorer), falling back to the
// modification time, sorted descending. Unrecognized entries fall back to sliding-window string
// extraction so names are not lost; if all else fails, fall back to string extraction of the whole body.
func shellbagNormalize(_ string, body string) *model.Shaped {
	blocks := regout.RegBlocks(body)
	type node struct {
		path []string
		item shellItem
	}
	var nodes []node
	var loose []string
	for _, block := range blocks {
		comps := bagMRUPath(block.Key)
		for _, value := range regout.ParseRegValues(block.Body) {
			if value.Type != "REG_BINARY" {
				continue
			}
			if _, err := strconv.Atoi(value.Name); err != nil {
				continue
			}
			data := regout.HexBytes(value.Data)
			item := parseShellItem(data)
			if item.kind == "unknown" {
				loose = append(loose, UTF16Strings(data, 2)...)
				item.name = value.Name
			}
			nodes = append(nodes, node{path: append(slices.Clone(comps), value.Name), item: item})
		}
	}

	byPath := make(map[string]shellItem, len(nodes))
	for _, n := range nodes {
		byPath[strings.Join(n.path, "\\")] = n.item
	}
	type line struct {
		when time.Time
		text string
	}
	var lines []line
	seen := map[string]bool{}
	for _, n := range nodes {
		if n.item.name == "" || n.item.kind == "unknown" {
			continue
		}
		// Leaf entries with unlisted GUIDs only serve as path-chain placeholders, not standalone spammy lines
		if strings.HasPrefix(n.item.name, "{") {
			continue
		}
		parts := make([]string, 0, len(n.path))
		for i := range n.path {
			part := byPath[strings.Join(n.path[:i+1], "\\")].name
			if part == "" {
				part = n.path[i]
			}
			parts = append(parts, part)
		}
		text := strings.Join(parts, "\\")
		if seen[text] {
			continue
		}
		seen[text] = true
		when := n.item.atime
		if when.IsZero() {
			when = n.item.mtime
		}
		lines = append(lines, line{when: when, text: text})
	}
	for _, text := range lo.Uniq(loose) {
		if guidOnly.MatchString(text) || seen[text] {
			continue
		}
		seen[text] = true
		lines = append(lines, line{text: text})
	}
	if len(lines) == 0 {
		// Structural parsing yielded nothing: fall back to the old sliding-window string extraction
		var texts []string
		for _, block := range blocks {
			for _, value := range regout.ParseRegValues(block.Body) {
				if value.Type == "REG_BINARY" {
					texts = append(texts, UTF16Strings(regout.HexBytes(value.Data), 2)...)
				}
			}
		}
		lines = lo.FilterMap(lo.Uniq(texts), func(text string, _ int) (line, bool) {
			return line{text: text}, !guidOnly.MatchString(text) && !seen[text]
		})
		if len(lines) == 0 {
			return nil
		}
	}
	// Descending time, zero values sink, ties by text: a zero-time Unix seconds value is a tiny negative
	// number that naturally sinks in descending order; entry times have second precision, so Unix comparison loses nothing
	slices.SortStableFunc(lines, func(a, b line) int {
		return cmp.Or(cmp.Compare(b.when.Unix(), a.when.Unix()), strings.Compare(a.text, b.text))
	})
	out := lo.Map(lines, func(l line, _ int) string {
		if l.when.IsZero() {
			return l.text
		}
		return l.when.Format("2006-01-02 15:04:05") + "  " + l.text
	})
	return &model.Shaped{Text: strings.Join(out, "\n")}
}

// bagMRUPath: components after BagMRU in a key path form the index chain; BagMRU itself gives an empty chain.
func bagMRUPath(key string) []string {
	at := strings.LastIndex(key, "BagMRU")
	if at < 0 {
		return nil
	}
	rest := strings.Trim(key[at+len("BagMRU"):], "\\")
	if rest == "" {
		return nil
	}
	return strings.Split(rest, "\\")
}

// NavigationChecks is the browsing and search aspect.
var NavigationChecks = []*model.Check{
	RegCheck("wordwheel-query", "Explorer Search Terms (WordWheelQuery)", model.AspectNavigation,
		wordwheelKeys,
		define.CheckOpt{
			Normalize: func(_ string, body string) *model.Shaped {
				return &model.Shaped{Text: strings.Join(MRUTerms(body, 2), "\n")}
			},
			Rules: []model.Rule{
				model.NewRule("wordwheel-sensitive", searchSensitive, model.High, "sensitive keyword searched"),
				define.KeywordRule,
			},
		}),
	RegCheck("typedpaths", "Address Bar Typed Paths (TypedPaths)", model.AspectNavigation,
		typedpathsKeys,
		define.CheckOpt{
			Syntax: "reg",
			Rules: []model.Rule{
				model.NewRule("typedpaths-nonlocal", nonlocalPath, model.Medium,
					"FTP or network share path typed in address bar"),
				define.KeywordRule,
			},
		}),
	RegCheck("shellbags", "Folder Browsing History (Shellbags, Path Recovery)", model.AspectNavigation,
		shellbagKeys,
		define.CheckOpt{
			Normalize: shellbagNormalize,
			Rules: []model.Rule{
				model.NewRule("shellbags-nonlocal", nonlocalPath, model.Medium, "FTP or network location browsed"),
			},
		}),
}
