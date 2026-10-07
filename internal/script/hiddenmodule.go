// The hidden-module diff of three views of one fact: which modules the kernel
// carries. The loader registers each module in /sys/module (a kobject with a
// sections/ directory), /proc/modules lists the modules in the list, and
// /proc/kallsyms tags every symbol with the module it came from. A module that
// unlinks itself leaves the other two; one that also drops its kobject leaves
// only the symbol tags. One row per name the views disagree about, carrying all
// three verdicts, so the panel says which registry is missing the module rather
// than only that something is.
//
// Both emitters produce one marked record stream — A an availability flag, S a
// sysfs module with its attributes, P a /proc/modules name, K a kallsyms tag
// with its symbol count — and one Go join renders it: HiddenModuleBody, which
// the check hangs on the tier as its Assemble.
//
// Two emitters, one join: this file's shell block (the sh source)
// and native.hiddenModuleViewsText (the local channel) produce the stream, and
// the shape is rendered in one place, so the join cannot drift between the two
// languages the way it could when the target ran its own awk mirror. The stream
// is a few lines per module. hiddenmodule_test.go pins the join over built
// streams; the linux catalog's test runs both emitters over one fixture tree
// and compares the streams, which is the half that can still drift.

package script

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"karma/internal/textutil"
)

// ModuleDiffViews are the three surfaces the diff reads, plus the attribute
// list and the symbol tags that are not modules. One value feeds both channels:
// the check builds it once and hands it to the in-process body and to the
// pipeline, so the two cannot read different paths, attributes or drop lists.
type ModuleDiffViews struct {
	// SysfsRoot is the module registry the loader populates (/sys/module);
	// a loadable module has a sections/ subdirectory there.
	SysfsRoot string
	// ModulesPath is the kernel's module list (/proc/modules).
	ModulesPath string
	// SymbolsPath is the symbol table whose tags name a symbol's module
	// (/proc/kallsyms).
	SymbolsPath string
	// Attrs are the "label:file" pairs read under /sys/module/<name>/ for a
	// module's evidence line; an attribute that does not read back is left out.
	Attrs []string
	// PseudoTags are the kallsyms tags that are not modules: JITed BPF programs
	// and the pages the kernel allocates for ftrace and kprobe trampolines.
	PseudoTags []string
}

// The view names the availability flags and the row verdicts use.
const (
	viewSysfs    = "sysfs"
	viewKallsyms = "kallsyms"
)

// HiddenModuleScript is the sh source's half of the diff: the marked
// stream the check's Assemble turns into rows. The three views travel in one
// script — a tier that stopped after the first would answer for the whole tier
// (an exit 0 with no rows is still an answer) and the chain would never reach
// the others. The module list has to be readable — it is the baseline every
// verdict is relative to — and a target that cannot give it exits 1, which the
// chain reads as an unavailable tier. The other two views report themselves
// unavailable instead (sysfs=?), so a half that is missing on the target does
// not turn into a verdict.
//
// The symbol count is folded on the target (moduleTagAwk): the table it counts
// in is megabytes and its quiet lines carry no evidence, so the fold belongs
// where the data is. Everything above the fold — the verdicts, the order, the
// rows — is the join's, and the join runs once, in Go.
func HiddenModuleScript(views ModuleDiffViews) string {
	var b strings.Builder
	b.WriteString("mods=" + views.ModulesPath + "\n")
	b.WriteString("[ -r \"$mods\" ] || exit 1\n")
	b.WriteString("{\n")
	b.WriteString("  [ -d " + views.SysfsRoot + " ] && echo \"A " + viewSysfs + " 1\" || echo \"A " + viewSysfs + " 0\"\n")
	b.WriteString("  [ -r " + views.SymbolsPath + " ] && echo \"A " + viewKallsyms + " 1\" || echo \"A " + viewKallsyms + " 0\"\n")
	b.WriteString("  for d in " + views.SysfsRoot + "/*; do\n")
	b.WriteString("    [ -d \"$d/sections\" ] || continue\n")
	b.WriteString("    n=${d##*/}\n")
	b.WriteString("    line=\"S $n\"\n")
	b.WriteString("    for pair in " + strings.Join(views.Attrs, " ") + "; do\n")
	b.WriteString("      v=\n")
	b.WriteString("      [ -f \"$d/${pair#*:}\" ] && read -r v < \"$d/${pair#*:}\"\n")
	b.WriteString("      [ -n \"$v\" ] && line=\"$line ${pair%%:*} $v\"\n")
	b.WriteString("    done\n")
	b.WriteString("    echo \"$line\"\n")
	b.WriteString("  done\n")
	b.WriteString("  awk '{print \"P \" $1}' \"$mods\" 2>/dev/null\n")
	b.WriteString("  " + moduleTagAwk(views.SymbolsPath, views.PseudoTags) + "\n")
	b.WriteString("}\n")
	return b.String()
}

// moduleTagAwk emits the K lines: one per module tag in the symbol table, with
// how many symbols carry it. The pseudo-module tags are dropped here, the way
// the in-process emitter drops them, so both counts mean the same thing. The
// lines are sorted by tag because awk's array iteration has no order: the stream
// is evidence, and two channels' — or two runs' — streams are diffed against
// each other (make parity), so a set must not travel in an arbitrary sequence.
func moduleTagAwk(symbolsPath string, pseudo []string) string {
	drops := make([]string, 0, len(pseudo))
	for _, tag := range pseudo {
		drops = append(drops, `n != "`+tag+`"`)
	}
	keep := "1"
	if len(drops) > 0 {
		keep = strings.Join(drops, " && ")
	}
	return fmt.Sprintf(`awk '{n=$NF; if (n ~ /^\[/) {gsub(/[][]/,"",n); if (%s) cnt[n]++}} `+
		`END {for (n in cnt) print "K " n " " cnt[n]}' %s 2>/dev/null | LC_ALL=C sort`,
		keep, symbolsPath)
}

// HiddenModuleBody is the join: the marked stream HiddenModuleScript and
// native.hiddenModuleViewsText emit, rendered as the rows the panel shows. Every
// name any view carries is printed once when the views disagree — HIDDEN when
// the module list has forgotten it, GAP when the list has it and the sysfs
// registry does not. A name only the symbol table is missing stays out: a kernel
// built without CONFIG_KALLSYMS_ALL tags few of its modules, and that is not a
// finding. The rows are ordered by module name (byte order, which is what the
// target's LC_ALL=C sort produced).
func HiddenModuleBody(marked string) string {
	attrs := map[string]string{}
	sysfsPresent := map[string]bool{}
	symbolCounts := map[string]int{}
	inProc := map[string]bool{}
	avail := map[string]bool{}

	for line := range textutil.Lines(marked) {
		field, rest, _ := strings.Cut(line, " ")
		switch field {
		case "A":
			name, value, _ := strings.Cut(rest, " ")
			avail[name] = value == "1"
		case "S":
			name, tail, _ := strings.Cut(rest, " ")
			sysfsPresent[name] = true
			attrs[name] = tail
		case "P":
			inProc[rest] = true
		case "K":
			name, count, _ := strings.Cut(rest, " ")
			value, err := strconv.Atoi(count)
			if err != nil {
				continue
			}
			symbolCounts[name] = value
		}
	}

	names := make([]string, 0, len(sysfsPresent)+len(inProc)+len(symbolCounts))
	for name := range sysfsPresent {
		names = append(names, name)
	}
	for name := range inProc {
		if !sysfsPresent[name] {
			names = append(names, name)
		}
	}
	for name := range symbolCounts {
		if !sysfsPresent[name] && !inProc[name] {
			names = append(names, name)
		}
	}
	slices.Sort(names)

	verdict := func(present, viewAvailable bool) string {
		switch {
		case present:
			return "yes"
		case viewAvailable:
			return "no"
		default:
			return "?"
		}
	}

	var b strings.Builder
	for _, name := range names {
		_, inSysfs := sysfsPresent[name]
		_, inSymbols := symbolCounts[name]
		sysfsVerdict := verdict(inSysfs, avail[viewSysfs])
		symbolsVerdict := verdict(inSymbols, avail[viewKallsyms])
		symbols := ""
		if inSymbols {
			symbols = fmt.Sprintf(" symbols %d", symbolCounts[name])
		}
		switch {
		case !inProc[name]:
			fmt.Fprintf(&b, "HIDDEN %s %s=%s proc=no %s=%s", name, viewSysfs, sysfsVerdict, viewKallsyms, symbolsVerdict)
			if attrs[name] != "" {
				b.WriteString(" " + attrs[name])
			}
			b.WriteString(symbols + "\n")
		case !inSysfs && avail[viewSysfs]:
			fmt.Fprintf(&b, "GAP %s %s=no proc=yes %s=%s%s\n", name, viewSysfs, viewKallsyms, symbolsVerdict, symbols)
		}
	}
	return b.String()
}
