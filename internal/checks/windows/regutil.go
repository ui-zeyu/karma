// Shared utilities for the Windows checks: PowerShell probe construction, reg output parsing, registry data decoding.
//
// The text shape of reg.exe (what karma parses):
//
//	HKEY_CURRENT_USER\Software\...\RunMRU
//	    MRUList    REG_SZ    nmb
//	    0    REG_BINARY    0C,00,00,00,...,\
//	        00,00,00,00
//
// Value rows are indented 4 spaces with 4 spaces between name and type; an overlong REG_BINARY wraps
// with a trailing `\`, continuation lines indented 8 or more spaces. All decoding happens locally:
// the probe only brings back hex and text, while ROT-13, UTF-16 extraction, FILETIME conversion, and
// MRUListEx list reconstruction are the job of the check's normalize.

package windows

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/samber/lo"

	"karma/internal/define"
	"karma/internal/model"
	"karma/internal/powershell"
	"karma/internal/regout"
)

// PSProbe turns a PowerShell script into a probe whose body is one unnamed
// section; requires is derived from argv[0], i.e. powershell.
func PSProbe(label string, script string) model.Probe {
	return model.Probe{Label: label, Inv: powershell.PowerShell(script)}
}

// PSKeyProbe is one registry key's PowerShell probe: the query alone, under the
// key's own section title, so the key's name is the collection's statement and
// never a line reg.exe happened to print.
func PSKeyProbe(label, title, pipeline string) model.Probe {
	return model.Probe{Label: label, Title: title, Inv: powershell.PowerShell(pipeline)}
}

// PSFilesProbe is a per-file probe: list answers with the paths, one per line,
// and read builds the script that reads one of them. It is the Windows spelling
// of the Linux catalog's file list, and it keeps every file's section titled with
// its path.
func PSFilesProbe(label, list string, read func(path string) string) model.Probe {
	return model.Probe{Label: label, Files: &model.Files{
		List: powershell.PowerShell(list),
		Read: func(path string) model.Invocation { return powershell.PowerShell(read(path)) },
	}}
}

// PSQuote renders one path as a PowerShell single-quoted string: the path the
// target answered with is spliced verbatim, with its own quotes doubled.
func PSQuote(path string) string {
	return "'" + strings.ReplaceAll(path, "'", "''") + "'"
}

// PSListPaths is the listing half of a per-file probe: every file of the globs,
// one full path per line. A path that cannot be read is not listed.
func PSListPaths(roots []string, filter string, recurse bool) string {
	quoted := make([]string, len(roots))
	for index, root := range roots {
		quoted[index] = PSQuote(root)
	}
	flags := " -File -ErrorAction SilentlyContinue"
	if filter != "" {
		flags = " -Filter '" + filter + "'" + flags
	}
	if recurse {
		flags = " -Recurse" + flags
	}
	return "Get-ChildItem " + strings.Join(quoted, ",") + flags +
		" | ForEach-Object { $_.FullName }"
}

// RegDirectProbe is the no-PowerShell fallback probe: reg.exe is exec'd directly, without any shell.
//
// Spaces in the key are preserved by argv boundaries (local exec does not reorder arguments). The
// key's section title travels on the probe, so the body is that key's lines and nothing else. An
// empty value means a recursive or whole-key query.
func RegDirectProbe(label string, key string, recurse bool, value string) model.Probe {
	argv := []string{"reg", "query", key}
	if value != "" {
		argv = append(argv, "/v", value)
	} else if recurse {
		argv = append(argv, "/s")
	}
	return model.Probe{Label: label, Title: regTitle(key, value), Inv: model.NewCommand(argv...)}
}

// regTitle is the section title of one registry surface: the key, and the value
// name when the query names one.
func regTitle(key, value string) string {
	if value == "" {
		return key
	}
	return key + "\\" + value
}

// RegPipeline is the PowerShell pipeline of one key's query: the command alone.
// The probe that runs it carries the key's section title.
func RegPipeline(key string, recurse bool) string {
	flag := ""
	if recurse {
		flag = " /s"
	}
	return fmt.Sprintf("reg query '%s'%s 2>$null", key, flag)
}

// RegValuePipeline is the pipeline of a single-value reg query.
func RegValuePipeline(key string, value string) string {
	return fmt.Sprintf("reg query '%s' /v %s 2>$null", key, value)
}

// RegKey is one registry key a check reads: the PowerShell probe queries it inside
// its composed script, and each key also carries its own direct reg.exe fallback
// probe, so a PS-less target keeps full coverage.
type RegKey struct {
	Path    string // key path, backslash-separated
	Recurse bool   // query subkeys recursively
	Value   string // non-empty queries one value instead of the whole key
	Label   string // fallback probe label, shown in the panel's probe chain
}

// fragment is the key's query pipeline.
func (k RegKey) fragment() string {
	if k.Value != "" {
		return RegValuePipeline(k.Path, k.Value)
	}
	return RegPipeline(k.Path, k.Recurse)
}

// title is the section this key answers with.
func (k RegKey) title() string { return regTitle(k.Path, k.Value) }

// RegCheck builds a registry check: one PowerShell probe per key (plus one per
// extra fragment), then one step of direct reg.exe probes, one per key, all of
// them answering together. The key list is written once and feeds both steps, so
// a key cannot end up in the PowerShell step without its fallback or the other way
// around, and both tiers title their sections with the same key.
//
// The reg.exe step is one step of several probes (model.Step): a target without
// PowerShell gets every key, one process each, because reg.exe takes one key and
// the local Windows channel has no shell to loop in — while one step per key
// would let the walk stop at the first key that exists and silently drop the rest
// of the evidence.
func RegCheck(id, title string, aspect model.Aspect, keys []RegKey, opt define.CheckOpt, extra ...ExtraFragment) *model.Check {
	inProcess := make(model.Step, 0, len(keys)+len(extra))
	for _, key := range keys {
		inProcess = append(inProcess, PSKeyProbe("reg", key.title(), key.fragment()))
	}
	for _, fragment := range extra {
		inProcess = append(inProcess, PSKeyProbe("reg", fragment.Title, fragment.Pipeline))
	}
	steps := []model.Step{inProcess}
	fallbacks := make(model.Step, 0, len(keys))
	for _, key := range keys {
		fallbacks = append(fallbacks, RegDirectProbe(key.Label, key.Path, key.Recurse, key.Value))
	}
	if len(fallbacks) > 0 {
		steps = append(steps, fallbacks)
	}
	return define.WindowsCheck(id, title, aspect, steps, opt)
}

// ExtraFragment is one further named surface of a registry check: a section the
// check reads with its own PowerShell pipeline (something that is not a plain reg
// query).
type ExtraFragment struct {
	Title    string
	Pipeline string
}

var printable = regexp.MustCompile(`[\x20-\x7E\x{4E00}-\x{9FFF}]{3,}`)

// UTF16Strings decodes binary as UTF-16LE and extracts printable strings; paths inside PIDL/word
// binaries all come through here. Names in shell items can fall on any byte phase: using only the
// even phase reads odd-aligned ASCII as fake CJK garbage (seen on real shellbags output), so both
// phases are extracted and misaligned fake strings are dropped whole.
func UTF16Strings(data []byte, minlen int) []string {
	var found []string
	seen := make(map[string]bool)
	collect := func(text string) {
		for _, s := range printable.FindAllString(text, -1) {
			if utf8.RuneCountInString(s) < minlen || seen[s] || misaligned(s) {
				continue
			}
			seen[s] = true
			found = append(found, s)
		}
	}
	collect(utf16Text(data, 0))
	if len(data) > 1 {
		collect(utf16Text(data, 1))
	}
	return found
}

// utf16Text decodes byte pairs as UTF-16LE text starting at the offset phase.
func utf16Text(data []byte, offset int) string {
	units := make([]uint16, 0, (len(data)-offset)/2)
	for i := offset; i+1 < len(data); i += 2 {
		units = append(units, binary.LittleEndian.Uint16(data[i:]))
	}
	return string(utf16.Decode(units))
}

// misaligned is a string read from the wrong phase: every character has a zero low byte and a high
// byte in printable ASCII--the shape of aligned ASCII text shifted by one byte. Real text (including
// CJK) almost never has all-zero low bytes.
func misaligned(text string) bool {
	if text == "" {
		return false
	}
	for _, r := range text {
		low, high := r&0xFF, r>>8
		if r >= 0x10000 || low != 0 || high < 0x20 || high > 0x7E {
			return false
		}
	}
	return true
}

// ROT13 restores UserAssist value names.
func ROT13(text string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case 'A' <= r && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		case 'a' <= r && r <= 'z':
			return 'a' + (r-'a'+13)%26
		}
		return r
	}, text)
}

// filetimeEpoch is the count of 100ns intervals from 1601-01-01 to 1970-01-01.
const filetimeEpoch = 116444736000000000

// FiletimeStr converts an 8-byte FILETIME to UTC text; empty when data is short, zero, or before the Unix epoch.
func FiletimeStr(data []byte) string {
	if len(data) < 8 {
		return ""
	}
	ticks := binary.LittleEndian.Uint64(data[:8])
	if ticks < filetimeEpoch {
		return ""
	}
	// subtract the epoch offset before converting, to avoid overflowing int64 when the 100ns count is multiplied by 100
	unixTicks := int64(ticks - filetimeEpoch)
	moment := time.Unix(unixTicks/1e7, (unixTicks%1e7)*100).UTC()
	return moment.Format("2006-01-02 15:04:05")
}

// MRUListExOrder returns the access order held by an MRUListEx array: the first
// element is the index of the most recent item and each subsequent element points
// to the next. The array is terminated by 0xFFFFFFFF; an out-of-range value or a
// cycle truncates the order obtained so far.
func MRUListExOrder(values []regout.Value) []int {
	raw, ok := lo.Find(values, func(v regout.Value) bool {
		return v.Name == "MRUListEx" && v.Type == "REG_BINARY"
	})
	if !ok {
		return nil
	}
	data := regout.HexBytes(raw.Data)
	count := len(data) / 4
	if count == 0 {
		return nil
	}
	entries := make([]uint32, count)
	for i := range entries {
		entries[i] = binary.LittleEndian.Uint32(data[i*4:])
	}
	var order []int
	seen := map[int]bool{}
	for index := int(entries[0]); index != 0xFFFFFFFF && 0 <= index && index < len(entries) && !seen[index]; index = int(entries[index]) {
		order = append(order, index)
		seen[index] = true
	}
	return order
}

// blockOrder prefers list order, falling back to ascending index when there is no list.
func blockOrder(order []int, indexes []int) []int {
	if len(order) > 0 {
		return order
	}
	sorted := slices.Clone(indexes)
	slices.Sort(sorted)
	return sorted
}

// MRUTerms for keys with numeric-named values plus MRUListEx (the WordWheelQuery/RecentDocs family)
// takes the first string in access order; without a list it uses ascending index.
func MRUTerms(body string, minlen int) []string {
	values := regout.ParseRegValues(body)
	order := MRUListExOrder(values)
	terms := make(map[int]string)
	var indexes []int
	for _, value := range values {
		index, err := strconv.Atoi(value.Name)
		if value.Name == "MRUListEx" || value.Type != "REG_BINARY" || err != nil {
			continue
		}
		if list := UTF16Strings(regout.HexBytes(value.Data), minlen); len(list) > 0 {
			terms[index] = list[0]
			indexes = append(indexes, index)
		}
	}
	order = blockOrder(order, indexes)
	return lo.FilterMap(order, func(index int, _ int) (string, bool) {
		term, ok := terms[index]
		return term, ok
	})
}

// KnownFolders maps known folder GUIDs used as shell item / UserAssist value name prefixes; unlisted
// ones are kept as-is (with braces stripped). The table comes from Velociraptor Windows.Forensics.Lnk
// profile's known folder list, plus common namespace roots.
var KnownFolders = map[string]string{
	"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": "System32",
	"{F38BF404-1D43-42F2-9305-67DE0B28FC23}": "Windows",
	"{6D809377-6AF0-444B-8957-A3773F02200E}": "ProgramFilesX64",
	"{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": "ProgramFiles(x86)",
	"{20D04FE0-3AEA-1069-A2D8-08002B30309D}": "MyComputer",
	"{DE61D971-5EBC-4F02-A3A9-6C82895E5C04}": "AddNewPrograms",
	"{724EF170-A42D-4FEF-9F26-B60E846FBA4F}": "AdminTools",
	"{A520A1A4-1780-4FF6-BD18-167343C5AF16}": "AppDataLow",
	"{A305CE99-F527-492B-8B1A-7E76FA98D6E4}": "AppUpdates",
	"{9E52AB10-F80D-49DF-ACB8-4330F5687855}": "CDBurning",
	"{DF7266AC-9274-4867-8D55-3BD661DE872D}": "ChangeRemovePrograms",
	"{D0384E7D-BAC3-4797-8F14-CBA229B392B5}": "CommonAdminTools",
	"{C1BAE2D0-10DF-4334-BEDD-7AA20B227A9D}": "CommonOEMLinks",
	"{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}": "CommonPrograms",
	"{A4115719-D62E-491D-AA7C-E74B8BE3B067}": "CommonStartMenu",
	"{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}": "CommonStartup",
	"{B94237E7-57AC-4347-9151-B08C6C32D1F7}": "CommonTemplates",
	"{0AC0837C-BBF8-452A-850D-79D08E667CA7}": "Computer",
	"{4BFEFB45-347D-4006-A5BE-AC0CB0567192}": "Conflict",
	"{6F0CD92B-2E97-45D1-88FF-B0D186B8DEDD}": "Connections",
	"{56784854-C6CB-462B-8169-88E350ACB882}": "Contacts",
	"{82A74AEB-AEB4-465C-A014-D097EE346D63}": "ControlPanel",
	"{2B0F765D-C0E9-4171-908E-08A611B84FF6}": "Cookies",
	"{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": "Desktop",
	"{FDD39AD0-238F-46AF-ADB4-6C85480369C7}": "Documents",
	"{088E3905-0323-4B02-9826-5D99428E115F}": "Downloads",
	"{374DE290-123F-4565-9164-39C4925E467B}": "Downloads",
	"{1777F761-68AD-4D8A-87BD-30B759FA33DD}": "Favorites",
	"{FD228CB7-AE11-4AE3-864C-16F3910AB8FE}": "Fonts",
	"{054FAE61-4DD8-4787-80B6-090220C4B700}": "GameTasks",
	"{CAC52C1A-B53D-4EDC-92D7-6B2E8AC19434}": "Games",
	"{D9DC8A3B-B784-432E-A781-5A1130A75963}": "History",
	"{4D9F7874-4E0C-4904-967B-40B0D20C3E4B}": "Internet",
	"{352481E8-33BE-4251-BA85-6007CAEDCF9D}": "InternetCache",
	"{BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968}": "Links",
	"{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}": "LocalAppData",
	"{2A00375E-224C-49DE-B8D1-440DF7EF3DDC}": "LocalizedResourcesDir",
	"{4BD8D571-6D19-48D3-BE97-422220080E43}": "Music",
	"{C5ABBF53-E17F-4121-8900-86626FC2C973}": "NetHood",
	"{D20BEEC4-5CA8-4905-AE3B-BF251EA09B53}": "Network",
	"{31C0DD25-9439-4F12-BF41-7FF4EDA38722}": "Objects3D",
	"{2C36C0AA-5812-4B87-BFD0-4CD0DFB19B39}": "OriginalImages",
	"{69D2CF90-FC33-4FB7-9A0C-EBB0F0FCB43C}": "PhotoAlbums",
	"{33E28130-4E1E-4676-835A-98395C3BC3BB}": "Pictures",
	"{DE92C1C7-837F-4F69-A3BB-86E631204A23}": "Playlists",
	"{9274BD8D-CFD1-41C3-B35E-B13F55A758F4}": "PrintHood",
	"{76FC4E2D-D6AD-4519-A663-37BD56068185}": "Printers",
	"{5E6C858F-0E22-4760-9AFE-EA3317B67173}": "Profile",
	"{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}": "ProgramData",
	"{905E63B6-C1BF-494E-B29C-65B732D3D21A}": "ProgramFiles",
	"{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}": "ProgramFilesCommon",
	"{6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D}": "ProgramFilesCommonX64",
	"{DE974D24-D9C6-4D3E-BF91-F4455120B917}": "ProgramFilesCommonX86",
	"{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}": "Programs",
	"{7B81BE6A-CE2B-4676-A29E-EB907A5126C5}": "Programs and Features",
	"{DFDF76A2-C82A-4D63-906A-5644AC457385}": "Public",
	"{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}": "PublicDesktop",
	"{ED4824AF-DCE4-45A8-81E2-FC7965083634}": "PublicDocuments",
	"{3D644C9B-1FB8-4F30-9B45-F670235F79C0}": "PublicDownloads",
	"{DEBF2536-E1A8-4C59-B6A2-414586476AEA}": "PublicGameTasks",
	"{3214FAB5-9757-4298-BB61-92A9DEAA44FF}": "PublicMusic",
	"{B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5}": "PublicPictures",
	"{2400183A-6185-49FB-A2D8-4A392A602BA3}": "PublicVideos",
	"{52A4F021-7B75-48A9-9F6B-4B87A210BC8F}": "QuickLaunch",
	"{AE50C081-EBD2-438A-8655-8A092E34987A}": "Recent",
	"{BD85E001-112E-431E-983B-7B15AC09FFF1}": "RecordedTV",
	"{B7534046-3ECB-4C18-BE4E-64CD4CB7D6AC}": "RecycleBin",
	"{8AD10C31-2ADB-4296-A8F7-E4701232C972}": "ResourceDir",
	"{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}": "RoamingAppData",
	"{EE32E446-31CA-4ABA-814F-A5EBD2FD6D5E}": "SEARCH_CSC",
	"{98EC0E18-2098-4D44-8644-66979315A281}": "SEARCH_MAPI",
	"{B250C668-F57D-4EE1-A63C-290EE7D1AA1F}": "SampleMusic",
	"{C4900540-2379-4C75-844B-64E6FAF8716B}": "SamplePictures",
	"{15CA69B3-30EE-49C1-ACE1-6B5EC372AFB5}": "SamplePlaylists",
	"{859EAD94-2E85-48AD-A71A-0969CB56A6CD}": "SampleVideos",
	"{4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4}": "SavedGames",
	"{7D1D3A04-DEBB-4115-95CF-2F29DA2920DA}": "SavedSearches",
	"{190337D1-B8CA-4121-A639-6D472D16972A}": "SearchHome",
	"{8983036C-27C0-404B-8F08-102D10DCFD74}": "SendTo",
	"{7B396E54-9EC5-4300-BE0A-2482EBAE1A26}": "SidebarDefaultParts",
	"{A75D362E-50FC-4FB7-AC2C-A8BEAA314493}": "SidebarParts",
	"{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}": "StartMenu",
	"{B97D20BB-F46A-4C97-BA10-5E3608430854}": "Startup",
	"{43668BF8-C14E-49B2-97C9-747784D784B7}": "SyncManager",
	"{289A9A43-BE44-4057-A41B-587A76D7E7F9}": "SyncResults",
	"{0F214138-B1D3-4A90-BBA9-27CBC0C5389A}": "SyncSetup",
	"{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": "SystemX86",
	"{A63293E8-664E-48DB-A079-DF759E0509F7}": "Templates",
	"{5B3749AD-B49F-49C1-83EB-15370FBD4882}": "TreeProperties",
	"{0762D272-C50A-4BB0-A382-697DCD729B80}": "UserProfiles",
	"{F3CE0F7C-4901-4ACC-8648-D5D44B04EF8F}": "UsersFiles",
	"{18989B1D-99B5-455B-841C-AB7C74E4DDFC}": "Videos",
	"{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}": "Videos",
}

var knownFolderRe = regexp.MustCompile(`^\{([0-9A-Fa-f-]{36})\}(?:\\|$)`)

// TranslateKnownFolder translates a GUID prefix at the start of a value name into a familiar
// directory name; unlisted ones keep the original name (with braces stripped).
func TranslateKnownFolder(name string) string {
	matched := knownFolderRe.FindStringSubmatch(name)
	if matched == nil {
		return name
	}
	guid := strings.ToUpper(matched[1])
	suffix := name[2+len(matched[1]):] // strip the {GUID} prefix
	if folder, ok := KnownFolders["{"+guid+"}"]; ok {
		return folder + suffix
	}
	return guid + suffix
}
