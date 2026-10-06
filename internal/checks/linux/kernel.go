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
	"regexp"

	"karma/internal/checks/linux/native"
	"karma/internal/define"
	"karma/internal/model"
	"karma/internal/script"
)

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

// rootkitSyms: the symbol families /proc/kallsyms leaks. Two halves: the
// program names of the public catalog (define.RootkitNames — a kit usually names
// its functions after itself, so `rkduck_init` and `singularity_hook` carry the
// sample's name) and the generic hook vocabulary the syscall-table and
// getdents-override families share (Diamorphine, Reptile, Heroinn, and the
// syy/h4x tutorials). A plain alternation so the same string serves the shell
// probe's ERE and the rule's RE2.
const rootkitSyms = define.RootkitNames + `|hide_module|module_hidden|hidden_files|` +
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
// carries: the size the module occupies, its refcount, its state and its taint
// letters. One list feeds both channels' output, so the ssh script cannot drift
// from the in-process read.
//
// The section addresses are deliberately out of this list. A module that has
// been hiding itself can leave its kernfs attributes in a stale state, and a
// read of `/sys/module/<name>/sections/<section>` then faults the reader
// instead of answering: measured on the lab VM with Diamorphine loaded, the
// section attributes answered EIO, and a lookup of the missing `.text` under
// that directory killed the reading process with SIGSEGV and left a kernel
// trace in the ring buffer. The five attributes below answered cleanly on the
// same module (`size 20480 refs 0 state live taint OE`), and a module's load
// address is what the module-memory check derives from /proc/vmallocinfo, a
// surface the rootkit cannot damage.
var hiddenModuleAttrs = []native.ModuleAttr{
	{Label: "size", File: "coresize"},
	{Label: "init", File: "initsize"},
	{Label: "refs", File: "refcnt"},
	{Label: "state", File: "initstate"},
	{Label: "taint", File: "taint"},
}

// hiddenModuleViews is the diff's one set of surfaces: the check hands the same
// value to the in-process body and to the pipeline, so the two channels read the
// same paths, attributes and pseudo-module tags.
var hiddenModuleViews = native.ModuleDiffViews(hiddenModuleAttrs)

// hiddenModuleScript is the whole diff as one tier, the way native.ModulesHidden
// is one body: the three views travel in one script — a tier that stopped after
// the first would answer for the whole tier (an exit 0 with no rows is still an
// answer) and the chain would never reach the others.
var hiddenModuleScript = script.HiddenModuleScript(hiddenModuleViews)

// moduleMemoryViews is the module-memory diff's surfaces and allocator lists:
// one value for both channels, so the pipeline and the in-process body cannot
// read different paths or classify an allocator differently.
var moduleMemoryViews = native.ModuleMemoryViews()

// KernelChecks covers the kernel.
var KernelChecks = []*model.Check{
	define.LinuxCheck("modules-load", "Boot-loaded modules (/etc/modules, modules-load.d)", model.AspectKernel,
		[]model.Step{{{Label: "cat", Inv: model.Dual{Run: native.ModulesLoad(modulesLoadPaths), Script: modulesLoadScript}}}},
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
		[]model.Step{
			{{Label: "lsmod", Inv: model.Dual{Run: native.Lsmod, Script: "lsmod"}}},
			{{Label: "proc-modules", Inv: model.Dual{Run: native.ProcModules, Script: "cat /proc/modules 2>/dev/null"}}},
		},
		define.CheckOpt{
			// The Used by tail can contain spaces, which the generic table word-by-word
			// coloring would split apart
			Syntax: model.SyntaxLsmod,
			Rules: []model.Rule{
				// Out-of-tree and unsigned are common on a healthy host (dkms, nvidia,
				// virtualbox), so both are leads rather than findings: what makes them
				// evidence is the module they belong to.
				model.NewRule("module-out-of-tree", `\([A-Z+-]*O[A-Z+-]*\)$`, model.Medium,
					"out-of-tree module (not from the distribution)"),
				model.NewRule("module-unsigned", `\([A-Z+-]*E[A-Z+-]*\)$`, model.Medium,
					"unsigned module (signature not verified)"),
				// The catalog's names on the module registry's own surface, where a name
				// is a module's identity: both tiers of this check print the module name
				// first, and the row's remaining columns are its facts. The word boundary
				// keeps the span on the name (a trailing \s would paint the column
				// separator) and still refuses a longer name that merely starts with one
				// (reptilian is not reptile). The rule is check-local because `Word ...`
				// is a shape any listing row can carry, while here the column is the
				// registry's.
				model.NewRule("known-rootkit-module", `^(?:`+define.RootkitNames+`)\b`,
					model.Critical, "module named after a known Linux rootkit"),
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
	// Three independent views of one fact — which modules the kernel carries —
	// and the check prints one row per name they disagree about. The loader
	// created a kobject for every module, so /sys/module keeps a directory with a
	// sections/ subdirectory after the module unlinked itself from the list;
	// kallsyms prints the module each of its symbols came from in brackets, which
	// a module cannot scrub without unloading. A rootkit that only edits the list
	// is caught by both other views, one that also removes its kobject is still
	// caught in the symbol table, and a module the list carries while the sysfs
	// registry has forgotten it is a GAP row of its own. Every view travels in
	// one tier: probes in a chain would let the first one's empty exit-0 diff
	// answer for the whole check.
	define.LinuxCheck("modules-hidden", "Hidden module cross-check (sysfs, kallsyms vs /proc/modules)", model.AspectKernel,
		[]model.Step{{{Label: "diff", Inv: model.Dual{Run: native.ModulesHidden(hiddenModuleViews), Script: hiddenModuleScript}}}},
		define.CheckOpt{
			Rules: []model.Rule{
				// The span carries the name: the reason is about that module, and the
				// evidence tail after it is the module's own description.
				model.NewRule("module-hidden", `^HIDDEN \S+`, model.Critical,
					"module hidden from /proc/modules"),
				// The other way the views can disagree: the module list still names
				// the module while the registry the loader populated has no kobject
				// for it. Stock hosts answer the two views alike (measured on a 5.15
				// and a 7.0 kernel: one direction is empty both ways), so this is a
				// lead rather than a verdict.
				model.NewRule("module-view-gap", `^GAP \S+`, model.Medium,
					"module in /proc/modules with no sysfs registry entry"),
			},
		}),
	// A third registry, and one no userspace rootkit can edit: a module's code
	// and data live in the vmalloc area, and /proc/vmallocinfo names the caller
	// of every live allocation. A module that removed its kobject and its list
	// entry leaves that allocation behind, so the check attributes each one
	// through the symbols inside it and reports the memory nothing accounts
	// for. The module lists and the symbol table are the other two views; this
	// one survives the case both of them lose.
	define.LinuxCheck("module-memory", "Module memory (vmalloc regions vs the module list)", model.AspectKernel,
		[]model.Step{{{Label: "vmap", Inv: model.Dual{
			Run:    native.ModuleMemory(moduleMemoryViews),
			Script: script.ModuleMemoryScript(moduleMemoryViews),
		}}}},
		define.CheckOpt{
			Rules: []model.Rule{
				// The row carries the range, the caller and the symbols inside, so
				// the analyst can read the same memory in /proc/kcore or in a dump.
				model.NewRule("module-memory-unowned", `^UNOWNED \S+`, model.Critical,
					"executable kernel memory belonging to no listed module"),
				// The accounting line is always shown: the number of allocations
				// the kernel's own allocators made against the number the module
				// list explains is what makes a rise in the unexplained count
				// visible across two runs.
				model.NewRule("module-memory-accounting", `^VMAP regions \d+ `, model.Low,
					"executable kernel memory accounting"),
			},
		}),
	// LKM rootkits cannot scrub their own symbols out of /proc/kallsyms: the
	// catalog's program names and the classic syscall-table override families
	// (Diamorphine, Reptile, the h4x/syy tutorials) leave their names in the
	// table and often a module tag in brackets. grep is both collector and
	// filter — no hit is a clean exit 1, which stays silent, exactly like
	// webshell-grep. The name list's false-positive rate is measured: over the
	// full symbol tables of a 7.0 desktop kernel and a 5.15 server kernel it
	// matched the loaded rootkit's tag and nothing else.
	define.LinuxCheck("kallsyms", "Kernel symbol table rootkit signatures (/proc/kallsyms)", model.AspectKernel,
		[]model.Step{{{Label: "grep", Inv: model.Dual{
			Run:    native.Kallsyms(kallsymsRe),
			Script: kallsymsScript,
		}, Cap: model.Scan(openScanLines)}}},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("kallsyms-rootkit", `\b(?:`+rootkitSyms+`)\b`, model.Critical,
					"known LKM rootkit symbol in the kernel symbol table"),
			},
		}),
	define.LinuxCheck("tainted", "Kernel tainted flags", model.AspectKernel,
		[]model.Step{{{Label: "tainted", Inv: model.Dual{Run: native.Tainted, Script: "cat /proc/sys/kernel/tainted 2>/dev/null"}}}},
		define.CheckOpt{
			Rules: []model.Rule{
				// The whole mask is the finding, not its first digit: the span is
				// what the panel paints, and what a reader needs is the number the
				// bits add up to (12288 is out-of-tree + unsigned), not the
				// leading 1.
				model.NewRule("kernel-tainted", `^[1-9][0-9]*`, model.Medium,
					"kernel tainted (non-zero)"),
			},
		}),
	// dmesg's module lines are the evidence surface for load activity; placed last,
	// before the big lsmod table. Locally the ring buffer is read through
	// syslog(2) in-process (native_dmesg_linux).
	define.LinuxCheck("dmesg", "Kernel module logs", model.AspectKernel,
		[]model.Step{{{Label: "dmesg", Inv: model.Dual{Run: native.Dmesg, Script: "dmesg"}}}},
		define.CheckOpt{
			Syntax:  model.SyntaxDmesg,
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
