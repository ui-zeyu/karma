// kernel: module list, module load logs, hidden-module cross-check, taint flags.
//
// lsmod only reads the /proc/modules kernel list, so a module-hiding rootkit will
// not appear there. Two independent registries catch one that has unlinked
// itself: /sys/module keeps the kobject the loader created (a loadable module has
// a sections/ directory, a built-in does not) and kallsyms tags every symbol with
// the module it came from. The marker at the end of a /proc/modules line names
// what a module is (out-of-tree, unsigned), and the taint bit reflects a tainted
// kernel.

package linux

import (
	"fmt"
	"regexp"
	"strings"

	"karma/internal/checks/linux/native"
	"karma/internal/define"
	"karma/internal/model"
	"karma/internal/script"
)

// moduleSigScript: build-time config: /proc/config.gz (IKCONFIG kernels) first,
// the distro /boot/config as fallback; both are narrowed to CONFIG_MODULE_SIG
// first. A full IKCONFIG dump is thousands of lines, and pouring it all into the
// check box would leave only the two rule-highlighted lines informative. When
// neither exists (custom kernel), an empty answer stays silent.
const moduleSigScript = "zcat /proc/config.gz 2>/dev/null | grep '^CONFIG_MODULE_SIG'" +
	` || grep "^CONFIG_MODULE_SIG" "/boot/config-$(uname -r)" 2>/dev/null`

// modulesLoadPaths are the boot-load surfaces the check covers: the Debian
// /etc/modules file and the systemd modules-load.d layers, of which only the
// writable ones are scanned (/usr and /lib belong to distro packages). The ssh
// loop and the local walk read the same list.
var modulesLoadPaths = []string{
	"/etc/modules",
	"/etc/modules-load.d/*.conf",
	"/run/modules-load.d/*.conf",
	"/usr/local/lib/modules-load.d/*.conf",
}

var modulesLoadScript = script.ReadFiles(modulesLoadPaths, `cat "$f"`, true)

// rootkitSyms: symbol-name families leaked into /proc/kallsyms by known LKM
// rootkits (Diamorphine, Reptile, Heroinn, and the syy/h4x syscall-table
// override tutorials). A plain alternation so the same string serves the shell
// probe's ERE and the rule's RE2.
const rootkitSyms = `diamorphine|reptile|heroin|hide_module|module_hidden|hidden_files|` +
	`hide_tcp4_port|hide_tcp6_port|hacked_getdents|hacked_kill|kernel_unlink|` +
	`find_sys_call_tbl|h4x_delete_module|h4x_getdents64|h4x_kill|h4x_tcp4_seq_show|` +
	`new_getdents|old_getdents|should_hide_file_name|should_hide_task_name|is_invisible|` +
	`syy_getdents|syy_kill`

// kallsymsRe is the family alternation the local walk filters with — the same
// text the rule grades and the script greps.
var kallsymsRe = regexp.MustCompile(rootkitSyms)

// kallsymsScript narrows to the rootkit families before the text leaves the
// target: the full table is megabytes and its quiet lines carry no evidence.
const kallsymsScript = "grep -aE '" + rootkitSyms + "' /proc/kallsyms 2>/dev/null"

// moduleDirs lists the out-of-tree drop points directly: distro-owned modules all
// live under the kernel/ subdirectory (tens of thousands of files), while rootkit
// .ko files land in the module root or the out-of-tree updates/dkms, extra,
// weak-updates and misc directories (the rc_kernel.ko in the Liaoyuan notes
// rootkit exercise sits in the module root); finding new .ko files tree-wide is a
// job for the mtime subcommand. Collection runs find -printf (epoch first) and
// clusters locally to mark outlier lines.
var moduleDirs = []string{
	"/lib/modules/$(uname -r)",
	"/lib/modules/$(uname -r)/updates",
	"/lib/modules/$(uname -r)/updates/dkms",
	"/lib/modules/$(uname -r)/extra",
	"/lib/modules/$(uname -r)/weak-updates",
	"/lib/modules/$(uname -r)/misc",
}

// hiddenModuleAttrs are the sysfs attributes a hidden module's evidence line
// carries: the size the module occupies, the address of its code, its refcount,
// its state and its taint letters. One list feeds both channels' output, so the
// ssh script cannot drift from the in-process read.
var hiddenModuleAttrs = []native.ModuleAttr{
	{Label: "size", File: "coresize"},
	{Label: "init", File: "initsize"},
	{Label: "refs", File: "refcnt"},
	{Label: "state", File: "initstate"},
	{Label: "taint", File: "taint"},
	{Label: "text", File: "sections/.text"},
}

// hiddenModuleScript is the whole cross-check as one tier, the way
// native.ModulesHidden is one body: the sysfs diff over the target's own
// registry, then the kallsyms diff. Both footprints travel in one script — a
// tier that stopped after the first would answer for the whole tier (an exit 0
// with no rows is still an answer) and the chain would never reach the second.
var hiddenModuleScript = hiddenModuleDiffText(hiddenModuleAttrs, "/sys/module", "/proc/modules", "/proc/kallsyms")

// hiddenModuleDiffText is that tier over given surfaces, the four the tests
// substitute a fixture for.
func hiddenModuleDiffText(attrs []native.ModuleAttr, sysfsRoot, modulesPath, symbolsPath string) string {
	return hiddenSysfsDiffText(attrs, sysfsRoot, modulesPath) + hiddenSymbolDiffText(modulesPath, symbolsPath)
}

// hiddenSysfsDiffText is the sysfs half: a module directory with a sections/
// subdirectory that /proc/modules does not list is hidden, and the loop gathers
// whichever attributes read back non-empty.
func hiddenSysfsDiffText(attrs []native.ModuleAttr, sysfsRoot, modulesPath string) string {
	pairs := make([]string, 0, len(attrs))
	for _, attr := range attrs {
		pairs = append(pairs, attr.Label+":"+attr.File)
	}
	return `for d in ` + sysfsRoot + `/*; do
  [ -d "$d/sections" ] || continue
  n=${d##*/}
  grep -q "^$n " ` + modulesPath + ` 2>/dev/null && continue
  line="HIDDEN $n"
  for pair in ` + strings.Join(pairs, " ") + `; do
    v=$(cat "$d/${pair#*:}" 2>/dev/null)
    [ -n "$v" ] && line="$line ${pair%%:*} $v"
  done
  echo "$line"
done
`
}

// hiddenSymbolDiffText is the kallsyms half over a given module list and symbol
// table: the module tags in the symbol table are a second registry, and one that
// /proc/modules does not name is a hidden module. JITed BPF programs are tagged
// [bpf] without being modules, so the tag is dropped. One awk pass reads the
// module list first and the symbol table second — no temporary file on the
// target — and the count is how many of the module's symbols are still there.
// The first operand is picked by name (ARGV[1]): the NR==FNR idiom reads the
// second file as the first when the module list is empty or unreadable. The two
// file operands are substituted, so the tests run this same pipeline over
// fixtures.
func hiddenSymbolDiffText(modulesPath, symbolsPath string) string {
	return fmt.Sprintf(`awk 'FILENAME == ARGV[1] {mods[$1]=1; next}
     {n=$NF; if (n ~ /^\[/ && n != "[bpf]") {gsub(/[][]/,"",n); if (!(n in mods)) print n}}' \
  %s %s 2>/dev/null | sort | uniq -c | sort -k2 |
while read -r count name; do echo "HIDDEN $name symbols $count"; done
exit 0
`, modulesPath, symbolsPath)
}

// KernelChecks covers the kernel.
var KernelChecks = []*model.Check{
	define.LinuxCheck("modules-load", "Boot-loaded modules (/etc/modules, modules-load.d)", model.AspectKernel,
		[]model.Probe{
			{Label: "cat", Inv: model.Dual{Run: native.ModulesLoad(modulesLoadPaths), Script: modulesLoadScript}},
		},
		define.CheckOpt{
			Rules: []model.Rule{
				// Exclude a leading /: an == section title is a file path and should not light
				// up as a module entry, otherwise a comment-only /etc/modules would produce an
				// empty box by matching the title
				model.NewRule("modules-boot-entry", `^[^#\n/]\S+`, model.Low,
					"module loaded at boot"),
			},
		}),
	// lsmod is a big all-modules table with little signal; placed at the end of the
	// aspect so it does not block the targeted checks before it. The one graded
	// shape is the taint marker: /proc/modules ends a tainted module's line with
	// its letters in parentheses ("(POE)": proprietary, out-of-tree, unsigned,
	// and a "-"/"+" inside for a module being unloaded or loaded), which the lsmod
	// binary does not print — that tier is the module list as the host tool lays
	// it out, so the rules fire on the raw tier alone.
	define.LinuxCheck("lsmod", "Kernel modules", model.AspectKernel,
		[]model.Probe{
			{Label: "lsmod", Inv: model.Dual{Run: native.Lsmod, Script: "lsmod"}},
			{Label: "proc-modules", Inv: model.Dual{Run: native.ProcModules, Script: "cat /proc/modules 2>/dev/null"}},
		},
		define.CheckOpt{
			// The Used by tail can contain spaces, which the generic table word-by-word
			// coloring would split apart
			Syntax: "lsmod",
			Rules: []model.Rule{
				// Out-of-tree and unsigned are common on a healthy host (dkms, nvidia,
				// virtualbox), so both are leads rather than findings: what makes them
				// evidence is the module they belong to.
				model.NewRule("module-out-of-tree", `\([A-Z+-]*O[A-Z+-]*\)$`, model.Medium,
					"out-of-tree module (not from the distribution)"),
				model.NewRule("module-unsigned", `\([A-Z+-]*E[A-Z+-]*\)$`, model.Medium,
					"unsigned module (signature not verified)"),
			},
		}),
	listingCheck("module-files", "Out-of-tree kernel modules (updates/dkms, extra, etc.)", model.AspectKernel,
		moduleDirs, 100,
		[]model.Rule{
			// The filename is at the end of an ls line (symlink lines carry " -> target", so
			// the rule ends with \s|$); modules.* metadata in the root and entries under the
			// kernel/ subdirectory are official content and are not flagged
			model.NewRule("module-files-out-of-tree", `\.ko(?:\.[a-z0-9]+)?(?:\s|$)`, model.Medium,
				"out-of-tree module file"),
		}),
	// A hidden module leaves two independent footprints, and the check diffs both
	// against /proc/modules. The loader created a kobject for every module, so
	// /sys/module keeps a directory with a sections/ subdirectory after the module
	// unlinked itself from the list; and kallsyms prints the module each of its
	// symbols came from in brackets, which a module cannot scrub without
	// unloading. A rootkit that only edits the list is therefore caught twice,
	// and one that also removes its kobject is still caught in the symbol table.
	// Both footprints run in one tier: two probes in a chain would let the first
	// one's empty exit-0 diff answer for the whole check, and the symbol table
	// would never be read.
	define.LinuxCheck("modules-hidden", "Hidden module cross-check (/sys/module and kallsyms vs /proc/modules)", model.AspectKernel,
		[]model.Probe{
			{Label: "diff", Inv: model.Dual{Run: native.ModulesHidden(hiddenModuleAttrs), Script: hiddenModuleScript}},
		},
		define.CheckOpt{
			Rules: []model.Rule{
				// The span carries the name: the reason is about that module, and the
				// evidence tail after it is the module's own description.
				model.NewRule("module-hidden", `^HIDDEN \S+`, model.Critical,
					"module hidden from /proc/modules"),
			},
		}),
	define.LinuxCheck("module-sig-config", "Kernel module signature config", model.AspectKernel,
		[]model.Probe{
			{Label: "zcat", Inv: model.Dual{Run: native.ModuleSig, Script: moduleSigScript}},
		},
		define.CheckOpt{
			Syntax: "env",
			Rules: []model.Rule{
				model.NewRule("module-sig-off", `^CONFIG_MODULE_SIG=(?:n|m)`, model.Medium, "module signing not enabled"),
				model.NewRule("module-sig-not-forced", `^CONFIG_MODULE_SIG_FORCE=n`, model.Medium,
					"unsigned modules still load"),
			},
		}),
	// LKM rootkits cannot scrub their own symbols out of /proc/kallsyms: the
	// families below (Diamorphine, Reptile, and the classic syscall-table
	// override tutorials) leave their names in the table and often a module tag
	// in brackets. grep is both collector and filter — no hit is a clean exit 1,
	// which stays silent, exactly like webshell-grep.
	define.LinuxCheck("kallsyms", "Kernel symbol table rootkit signatures (/proc/kallsyms)", model.AspectKernel,
		[]model.Probe{
			{Label: "grep", Inv: model.Dual{
				Run:    native.Kallsyms(kallsymsRe),
				Script: kallsymsScript,
			}, LineLimit: 200},
		},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("kallsyms-rootkit", `\b(?:`+rootkitSyms+`)\b`, model.Critical,
					"known LKM rootkit symbol in the kernel symbol table"),
			},
		}),
	define.LinuxCheck("tainted", "Kernel tainted flags", model.AspectKernel,
		[]model.Probe{
			{Label: "tainted", Inv: model.Dual{Run: native.Tainted, Script: "cat /proc/sys/kernel/tainted 2>/dev/null"}},
		},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("kernel-tainted", `^[1-9]`, model.Medium,
					"kernel tainted (non-zero)"),
			},
		}),
	// dmesg's module lines are the evidence surface for load activity; placed last,
	// before the big lsmod table. Locally the ring buffer is read through
	// syslog(2) in-process (native_dmesg_linux).
	define.LinuxCheck("dmesg", "Kernel module logs", model.AspectKernel,
		[]model.Probe{{Label: "dmesg", Inv: model.Dual{Run: native.Dmesg, Script: "dmesg"}}},
		define.CheckOpt{
			Syntax:  "dmesg",
			Filters: dmesgKeepFilters,
			Rules: []model.Rule{
				model.NewRule("dmesg-taint", `(?i)\btaint`, model.Medium,
					"kernel tainted (dmesg)"),
				model.NewRule("dmesg-syscall-hook",
					`(?i)(?:\w*(?:sys_call_table|kallsyms_lookup_name)\w*|syscall\s+table|__NR_\w+)`,
					model.High, "syscall table lookup or rewrite (LKM hook evidence)"),
			},
		}),
}

// dmesgKeepFilters are the ring-buffer allowlists: what the loader logs, and the
// vocabulary a hooked kernel prints. A rootkit's printk rarely says "module", but
// it does print the syscall table pointer it found, the symbol lookup it needed
// and the syscalls it replaced, so `sys_call_table`, `__NR_…`, `hook…` and
// `getdents…` are the words to keep. Stock messages carry almost none of them —
// the kernel's own "Write protecting the read-only data" line is the reason
// `protect` is not in the list — and the panel collapses the quiet rows that do
// come through. A line carrying a signal bypasses the filters entirely, so the
// allowlist cannot hide a match.
var dmesgKeepFilters = []model.LineFilter{
	// load/taint records in the kernel ring plus module-load activity logged by
	// systemd (Inserted module etc., not in the ring)
	model.NewFilter("dmesg-module", `(?i)module`, model.FilterKeep),
	model.NewFilter("dmesg-integrity",
		`(?i)(?:sys_call_table|syscall\s+table|kallsyms_lookup_name|__NR_|`+
			`getdents\d*|hook\w*|cr0)`,
		model.FilterKeep),
}
