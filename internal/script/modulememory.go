// The module-memory diff: which executable kernel memory belongs to no module
// the registry lists. A module's code and data are allocated from the vmalloc
// area — the loader calls move_module (module_alloc on older kernels), which
// since 6.10 is one execmem_alloc allocation the kernel also uses for JITed BPF
// programs, kprobe and ftrace trampolines. /proc/vmallocinfo names the caller of
// every live allocation, so the regions a module owns are visible there even
// when the module has scrubbed itself out of /proc/modules and /sys/module: the
// allocation is a page-table fact, and no userspace rootkit can unlink it.
//
// Regions are attributed by the symbols inside them (/proc/kallsyms tags every
// symbol with the module it came from, and the pseudo-module tags name the
// kernel's own executable allocations) and by the allocator: an unexplained
// region from a module-only allocator is a module's memory with no registry
// entry, which is the kobject_del case the /sys and kallsyms diffs cannot see.
//
// Two implementations render the same rows: this file's Go side
// (ModuleMemoryBody, the local channel) and the pipeline the ssh and ttyd
// channels run (ModuleMemoryScript). Both read the same marked stream — R a
// vmalloc region, P a module-list name, Y a symbol inside a region — and
// modulememory_test.go runs them over one fixture and compares.

package script

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"karma/internal/textutil"
)

// ModuleMemoryViews are the surfaces the module-memory diff reads, plus the two
// allocator lists that tell a module's own memory from memory a module shares
// with BPF, kprobes and ftrace. One value feeds both channels.
type ModuleMemoryViews struct {
	// VMallocPath is the live vmalloc allocation list (/proc/vmallocinfo,
	// root-only): each line carries the address range, the size and the caller.
	VMallocPath string
	// ModulesPath is the kernel's module list (/proc/modules).
	ModulesPath string
	// SymbolsPath is the symbol table whose tags name a symbol's module
	// (/proc/kallsyms).
	SymbolsPath string
	// ModuleAllocators are the callers only the module loader uses: a live
	// allocation from one of them is a module's memory.
	ModuleAllocators []string
	// SharedAllocators are the callers modules share with the kernel's own
	// executable allocations (JITed BPF programs, kprobe and ftrace
	// trampolines): an unexplained region from one of them is a lead.
	SharedAllocators []string
	// PseudoTags are the kallsyms tags that are not modules: the tags the
	// kernel gives its own executable allocations.
	PseudoTags []string
	// CorePath is the running kernel's own core file (/proc/kcore). Only the
	// local channel can read it: the dig behind the rows goes through it to name
	// the memory nothing else explains, and a remote shell has no way to. The
	// pipeline ignores this field.
	CorePath string
}

// UnownedRegion is one region the join could not explain: the range and size as
// the row prints them, and the same range as numbers. A caller that can read the
// memory behind it (the local channel's core dig) takes the numbers, so it never
// has to parse the row back; the spelling stays the one /proc/vmallocinfo wrote,
// so a dig's row and the row it belongs to name the same bytes.
type UnownedRegion struct {
	Range      string // "0xstart-0xend", as the UNOWNED row spells it
	Start, End uint64
	Size       int
	Caller     string // the allocator class: module or shared
}

// The allocator class words the region rows carry and the join grades on.
const (
	allocModule = "module"
	allocShared = "shared"
)

// ModuleMemoryScript is the ssh and ttyd channels' tier: the regions, the module
// list and the symbols inside the regions in one block, joined by one awk pass.
// Both the allocation list and the module list have to be readable — without
// the first there is nothing to check, without the second no region can be
// explained — and a target that cannot give them exits 1, which the chain reads
// as an unavailable tier.
func ModuleMemoryScript(views ModuleMemoryViews) string {
	var b strings.Builder
	b.WriteString("vmi=" + views.VMallocPath + "\n")
	b.WriteString("mods=" + views.ModulesPath + "\n")
	b.WriteString("[ -r \"$vmi\" ] && [ -r \"$mods\" ] || exit 1\n")
	b.WriteString("{\n")
	b.WriteString("  " + moduleRegionAwk(views) + "\n")
	b.WriteString("  awk '{print \"P \" $1}' \"$mods\" 2>/dev/null\n")
	b.WriteString("  " + moduleSymbolAwk(views) + "\n")
	b.WriteString("} | awk -v pseudo=\"" + strings.Join(views.PseudoTags, " ") + "\" '" + moduleMemoryAwk() + "'\n")
	return b.String()
}

// moduleAllocatorClass maps a caller function name to its class, as the awk
// program's table: "move_module:module,module_alloc:module,execmem_alloc:shared".
func moduleAllocatorClass(views ModuleMemoryViews) string {
	pairs := make([]string, 0, len(views.ModuleAllocators)+len(views.SharedAllocators))
	for _, name := range views.ModuleAllocators {
		pairs = append(pairs, name+":"+allocModule)
	}
	for _, name := range views.SharedAllocators {
		pairs = append(pairs, name+":"+allocShared)
	}
	return strings.Join(pairs, ",")
}

// moduleRegionAwk emits the R lines: one per live allocation whose caller is one
// of the allocator functions, in the order /proc/vmallocinfo lists them, with
// the index the symbol pass uses for the same region.
func moduleRegionAwk(views ModuleMemoryViews) string {
	return fmt.Sprintf(`awk -v alloc="%s" '
  BEGIN { n = split(alloc, a, ","); for (i = 1; i <= n; i++) { split(a[i], kv, ":"); klass[kv[1]] = kv[2] } }
  {
    caller = $3
    sub(/\+.*$/, "", caller)
    if (!(caller in klass)) next
    split($1, range, "-")
    print "R " ++idx " " range[1] " " range[2] " " $2 " " klass[caller]
  }' %s`, moduleAllocatorClass(views), views.VMallocPath)
}

// moduleSymbolAwk emits the Y lines: every symbol that falls inside one of those
// regions, tagged with the module kallsyms names it as. The ranges are compared
// as fixed-width lowercase hex strings — awk has no hex conversion — which
// order the same way the numbers do. The region index is the same one the R
// pass assigned, both passes reading /proc/vmallocinfo in file order. An
// untagged symbol is emitted as "-": it is a published kernel address, which is
// what explains a region whose symbols name no module.
func moduleSymbolAwk(views ModuleMemoryViews) string {
	allocators := slices.Concat(views.ModuleAllocators, views.SharedAllocators)
	return fmt.Sprintf(`awk '
  function norm(h,   s) { sub(/^0x/, "", h); s = tolower(h); while (length(s) < 16) s = "0" s; return s }
  FILENAME == ARGV[1] {
    caller = $3
    sub(/\+.*$/, "", caller)
    if (caller !~ /^(%s)$/) next
    split($1, range, "-")
    lo[++nr] = norm(range[1]); hi[nr] = norm(range[2])
    next
  }
  {
    a = norm($1)
    for (i = 1; i <= nr; i++) {
      if (a >= lo[i] && a < hi[i]) {
        tag = "-"
        if ($NF ~ /^\[/) { tag = $NF; gsub(/[][]/, "", tag) }
        print "Y " i " " tag
        break
      }
    }
  }' %s %s 2>/dev/null`, strings.Join(allocators, "|"), views.VMallocPath, views.SymbolsPath)
}

// moduleMemoryAwk is the join, the mirror of ModuleMemoryBody: a region is
// explained when every symbol in it is either a pseudo-module tag, an untagged
// kernel symbol, or a module the list carries; the rest is reported. A region
// with no symbols at all is unexplained too — that is the shape a payload
// copied into module memory leaves (kopycat) — and it is printed only when the
// allocator is the module loader's own, because on a kernel whose modules share
// execmem_alloc with BPF and kprobes an anonymous region is the kernel's
// business (28 of them on a stock 7.0 desktop). The accounting line closes the
// report, so the analyst can see how much executable memory was not named.
func moduleMemoryAwk() string {
	return `BEGIN {
  np = split(pseudo, names, " ")
  for (k = 1; k <= np; k++) ptags[names[k]] = 1
  nr = 0; modules = 0; explained = 0; unexplained = 0
}
$1 == "R" { i = $2; raw_lo[i] = $3; raw_hi[i] = $4; size[i] = $5; class[i] = $6; nr = (i > nr ? i : nr); next }
$1 == "P" { listed[$2] = 1; modules++; next }
$1 == "Y" { i = $2; t = $3; count[i, t]++; if (!((i, t) in seen)) { seen[i, t] = 1; order[i] = order[i] " " t }; next }
END {
  for (i = 1; i <= nr; i++) {
    ok = (order[i] != "")
    if (ok) {
      n = split(order[i], tags, " ")
      for (k = 1; k <= n; k++) {
        t = tags[k]
        if (t != "-" && !(t in ptags) && !(t in listed)) ok = 0
      }
    }
    if (ok) { explained++; continue }
    unexplained++
    labels = ""
    if (order[i] != "") {
      n = split(order[i], tags, " ")
      for (k = 1; k <= n; k++) labels = labels " " tags[k] " " count[i, tags[k]]
    }
    if (class[i] == "` + allocModule + `" || labels != "") {
      print "UNOWNED " raw_lo[i] "-" raw_hi[i] " size " size[i] " caller " class[i] labels
    }
  }
  print "VMAP regions " nr " modules " modules " explained " explained " unexplained " unexplained
}`
}

// ModuleMemoryRows is the local channel's join over the same marked stream
// ModuleMemoryScript produces, rendering the rows that script's awk mirror
// renders, in the same order: one row per region nothing explains, then the
// accounting line. The views are the same value the pipeline is built from: the
// pseudo-module tags are the one piece of that configuration the join itself
// needs, because it is what tells an explained region from a hidden one.
//
// The regions the rows name come back with them, so a caller can go on to read
// the memory they point at.
func ModuleMemoryRows(views ModuleMemoryViews, marked string) ([]string, []UnownedRegion) {
	type region struct {
		rawStart string
		rawEnd   string
		size     int
		class    string
	}
	var order []int
	regions := map[int]*region{}
	listed := map[string]bool{}
	pseudo := map[string]bool{}
	counts := map[int]map[string]int{}
	symbolOrder := map[int][]string{}
	untagged := map[int]bool{}
	modules := 0

	for line := range textutil.Lines(marked) {
		field, rest, _ := strings.Cut(line, " ")
		switch field {
		case "R":
			index, tail, _ := strings.Cut(rest, " ")
			id, err := strconv.Atoi(index)
			if err != nil {
				continue
			}
			if _, seen := regions[id]; !seen {
				order = append(order, id)
			}
			start, tail, _ := strings.Cut(tail, " ")
			end, tail, _ := strings.Cut(tail, " ")
			size, tail, _ := strings.Cut(tail, " ")
			bytes, err := strconv.Atoi(size)
			if err != nil {
				continue
			}
			regions[id] = &region{rawStart: start, rawEnd: end, size: bytes, class: tail}
		case "P":
			listed[rest] = true
			modules++
		case "Y":
			index, tag, _ := strings.Cut(rest, " ")
			id, err := strconv.Atoi(index)
			if err != nil {
				continue
			}
			if tag == "-" {
				untagged[id] = true
				continue
			}
			if counts[id] == nil {
				counts[id] = map[string]int{}
			}
			if counts[id][tag] == 0 {
				symbolOrder[id] = append(symbolOrder[id], tag)
			}
			counts[id][tag]++
		}
	}
	// The pseudo-module tags are the one piece of the views the join needs:
	// whether a region's symbols name the kernel's own executable allocations.
	for _, tag := range views.PseudoTags {
		pseudo[tag] = true
	}

	explained := 0
	unexplained := 0
	var (
		rows    []string
		unowned []UnownedRegion
	)
	for _, id := range order {
		tags := symbolOrder[id]
		ok := len(tags) > 0 || untagged[id]
		for _, tag := range tags {
			if !pseudo[tag] && !listed[tag] {
				ok = false
			}
		}
		entry := regions[id]
		if ok {
			explained++
			continue
		}
		unexplained++
		var labels strings.Builder
		for _, tag := range tags {
			fmt.Fprintf(&labels, " %s %d", tag, counts[id][tag])
		}
		if entry.class == allocModule || labels.Len() > 0 {
			rows = append(rows, fmt.Sprintf("UNOWNED %s-%s size %d caller %s%s",
				entry.rawStart, entry.rawEnd, entry.size, entry.class, labels.String()))
			unowned = append(unowned, UnownedRegion{
				Range:  entry.rawStart + "-" + entry.rawEnd,
				Start:  parseAddress(entry.rawStart),
				End:    parseAddress(entry.rawEnd),
				Size:   entry.size,
				Caller: entry.class,
			})
		}
	}
	rows = append(rows, fmt.Sprintf("VMAP regions %d modules %d explained %d unexplained %d",
		len(order), modules, explained, unexplained))
	return rows, unowned
}

// ModuleMemoryBody is the rendering of those rows: the local channel's whole
// body, byte for byte what ModuleMemoryScript's awk prints.
func ModuleMemoryBody(views ModuleMemoryViews, marked string) string {
	rows, _ := ModuleMemoryRows(views, marked)
	return strings.Join(rows, "\n") + "\n"
}

// parseAddress reads one /proc/vmallocinfo address. A shape the kernel does not
// write leaves zero, which no memory is mapped at, so a dig over it reads
// nothing rather than the wrong bytes.
func parseAddress(text string) uint64 {
	value, err := strconv.ParseUint(strings.TrimPrefix(text, "0x"), 16, 64)
	if err != nil {
		return 0
	}
	return value
}
