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

// shellbagNormalize parses BagMRU values into a browsing timeline: the key path
// (the index chain after BagMRU) is the parent chain the full paths are joined
// from, and each row is `time  path`, the access time first with the modification
// time as the fallback, newest first. Values whose shell item could not be read
// contribute their own UTF-16 strings, and a body that yields nothing
// structurally is read as plain strings. An empty result is nil: the check stays
// silent.
func shellbagNormalize(_ string, body string) *model.Shaped {
	blocks := regout.RegBlocks(body)
	nodes, loose := shellbagNodes(blocks)
	seen := map[string]bool{}
	lines := append(shellbagFolders(nodes, seen), shellbagLoose(loose, seen)...)
	if len(lines) == 0 {
		if lines = shellbagFromBody(blocks, seen); len(lines) == 0 {
			return nil
		}
	}
	return &model.Shaped{Text: shellbagTimeline(lines)}
}

// shellbagNode is one BagMRU value: the index chain that reaches it — the key
// path after BagMRU plus the value's own name — and the shell item it decoded to.
type shellbagNode struct {
	path []string
	item shellItem
}

// shellbagLine is one row of the timeline: a folder and the time it was opened,
// zero when the item carried no time.
type shellbagLine struct {
	when time.Time
	text string
}

// shellbagNodes decodes every BagMRU value: an index-named REG_BINARY value is one
// shell item, and a value whose item is unrecognized also contributes the strings
// its own bytes carry.
func shellbagNodes(blocks []regout.Block) ([]shellbagNode, []string) {
	var nodes []shellbagNode
	var loose []string
	for _, block := range blocks {
		chain := bagMRUPath(block.Key)
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
			nodes = append(nodes, shellbagNode{path: append(slices.Clone(chain), value.Name), item: item})
		}
	}
	return nodes, loose
}

// shellbagFolders joins each entry's chain into a full path. An ancestor is named
// by the item decoded at its own chain, and one the chain does not carry keeps its
// index. An entry named by a bare GUID is a placeholder in the chain rather than a
// place someone browsed, so it contributes no row of its own.
func shellbagFolders(nodes []shellbagNode, seen map[string]bool) []shellbagLine {
	names := make(map[string]string, len(nodes))
	for _, node := range nodes {
		names[shellbagKey(node.path)] = node.item.name
	}
	var lines []shellbagLine
	for _, node := range nodes {
		if node.item.name == "" || node.item.kind == "unknown" || strings.HasPrefix(node.item.name, "{") {
			continue
		}
		parts := make([]string, 0, len(node.path))
		for depth := range node.path {
			part := names[shellbagKey(node.path[:depth+1])]
			if part == "" {
				part = node.path[depth]
			}
			parts = append(parts, part)
		}
		text := strings.Join(parts, `\`)
		if seen[text] {
			continue
		}
		seen[text] = true
		when := node.item.atime
		if when.IsZero() {
			when = node.item.mtime
		}
		lines = append(lines, shellbagLine{when: when, text: text})
	}
	return lines
}

// shellbagLoose adds what an unreadable value carried, first occurrence only and
// never a bare GUID.
func shellbagLoose(loose []string, seen map[string]bool) []shellbagLine {
	var lines []shellbagLine
	for _, text := range lo.Uniq(loose) {
		if guidOnly.MatchString(text) || seen[text] {
			continue
		}
		seen[text] = true
		lines = append(lines, shellbagLine{text: text})
	}
	return lines
}

// shellbagFromBody is the last resort: every binary value of the whole body read
// as strings, which is all that is left when no value carries an index name.
func shellbagFromBody(blocks []regout.Block, seen map[string]bool) []shellbagLine {
	var texts []string
	for _, block := range blocks {
		for _, value := range regout.ParseRegValues(block.Body) {
			if value.Type == "REG_BINARY" {
				texts = append(texts, UTF16Strings(regout.HexBytes(value.Data), 2)...)
			}
		}
	}
	return lo.FilterMap(lo.Uniq(texts), func(text string, _ int) (shellbagLine, bool) {
		return shellbagLine{text: text}, !guidOnly.MatchString(text) && !seen[text]
	})
}

// shellbagKey is one index chain as a map key: the components backslash-joined,
// which is also how the timeline joins a path.
func shellbagKey(path []string) string { return strings.Join(path, `\`) }

// shellbagTimeline renders the rows newest first, ties by text. A zero time's Unix
// seconds are a large negative number, so an entry with no time sinks to the end
// of a descending sort; entry times have second precision, so comparing them as
// Unix seconds loses nothing.
func shellbagTimeline(lines []shellbagLine) string {
	slices.SortStableFunc(lines, func(a, b shellbagLine) int {
		return cmp.Or(cmp.Compare(b.when.Unix(), a.when.Unix()), strings.Compare(a.text, b.text))
	})
	rows := make([]string, len(lines))
	for i, line := range lines {
		if line.when.IsZero() {
			rows[i] = line.text
			continue
		}
		rows[i] = line.when.Format("2006-01-02 15:04:05") + "  " + line.text
	}
	return strings.Join(rows, "\n")
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
			Rules: []model.Matcher{
				model.NewRule("wordwheel-sensitive", searchSensitive, model.High, "sensitive keyword searched"),
				define.KeywordRule,
			},
		}),
	RegCheck("typedpaths", "Address Bar Typed Paths (TypedPaths)", model.AspectNavigation,
		typedpathsKeys,
		define.CheckOpt{
			Syntax: model.SyntaxReg,
			Rules: []model.Matcher{
				model.NewRule("typedpaths-nonlocal", nonlocalPath, model.Medium,
					"FTP or network share path typed in address bar"),
				define.KeywordRule,
			},
		}),
	RegCheck("shellbags", "Folder Browsing History (Shellbags, Path Recovery)", model.AspectNavigation,
		shellbagKeys,
		define.CheckOpt{
			Normalize: shellbagNormalize,
			Rules: []model.Matcher{
				model.NewRule("shellbags-nonlocal", nonlocalPath, model.Medium, "FTP or network location browsed"),
			},
		}),
}
