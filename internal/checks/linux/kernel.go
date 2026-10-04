// kernel: module list, module load logs, hidden-module cross-check, taint flags.
//
// lsmod only reads the /proc/modules kernel list, so a module-hiding rootkit will
// not appear there. Loadable modules have a sections/ directory under
// /sys/module/<name>/ (built-ins do not); cross-checking finds modules that exist
// but are not registered. The taint bit reflects a tainted kernel.
package linux

import (
	"strings"

	"karma/internal/define"
	"karma/internal/model"
	"karma/internal/script"
)

const hiddenModuleScript = `
for d in /sys/module/*; do
  [ -d "$d/sections" ] || continue
  n=${d##*/}
  grep -q "^$n " /proc/modules 2>/dev/null || echo "HIDDEN $n"
done
`

// moduleSigScript: build-time config: /proc/config.gz (IKCONFIG kernels) first,
// the distro /boot/config as fallback; both are narrowed to CONFIG_MODULE_SIG
// first. A full IKCONFIG dump is thousands of lines, and pouring it all into the
// check box would leave only the two rule-highlighted lines informative. When
// neither exists (custom kernel), an empty answer stays silent.
const moduleSigScript = "zcat /proc/config.gz 2>/dev/null | grep '^CONFIG_MODULE_SIG'" +
	` || grep "^CONFIG_MODULE_SIG" "/boot/config-$(uname -r)" 2>/dev/null`

// modulesLoadScript: boot-time load surface: /etc/modules is the Debian
// convention and modules-load.d the systemd one; only the writable layers (/etc,
// /run, /usr/local) are scanned, since /usr and /lib belong to distro packages.
var modulesLoadScript = strings.Join([]string{
	script.ReadFiles([]string{"/etc/modules"}, `cat "$f"`, true),
	script.ReadFiles([]string{
		"/etc/modules-load.d/*.conf",
		"/run/modules-load.d/*.conf",
		"/usr/local/lib/modules-load.d/*.conf",
	}, `cat "$f"`, true),
}, "\n")

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

// KernelChecks covers the kernel.
var KernelChecks = []*model.Check{
	define.LinuxCheck("modules-load", "Boot-loaded modules (/etc/modules, modules-load.d)", model.AspectKernel,
		[]model.Probe{{Label: "cat", Inv: model.Shell{Script: modulesLoadScript}}},
		define.CheckOpt{
			Rules: []model.Rule{
				// Exclude a leading /: an == section title is a file path and should not light
				// up as a module entry, otherwise a comment-only /etc/modules would produce an
				// empty box by matching the title
				model.NewRule("modules-boot-entry", `^[^#\n/]\S+`, model.Low,
					"module loaded at boot (compare lsmod and modinfo to judge origin)"),
			},
		}),
	define.LinuxCheck("modules-hidden", "Hidden module cross-check (/sys/module vs /proc/modules)", model.AspectKernel,
		[]model.Probe{{Label: "shell", Inv: model.Shell{Script: hiddenModuleScript}}},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("module-hidden", `^HIDDEN `, model.Critical,
					"loadable module missing from /proc/modules (hidden-module sign, LKM rootkit hunt)"),
			},
		}),
	define.ListingCheck("module-files", "Out-of-tree kernel modules (updates/dkms, extra, etc.)", model.AspectKernel,
		moduleDirs, 100,
		[]model.Rule{
			// The filename is at the end of an ls line (symlink lines carry " -> target", so
			// the rule ends with \s|$); modules.* metadata in the root and entries under the
			// kernel/ subdirectory are official content and are not flagged
			model.NewRule("module-files-out-of-tree", `\.ko(?:\.[a-z0-9]+)?(?:\s|$)`, model.Medium,
				"module file in an out-of-tree or module-root directory (check package ownership for origin)"),
		}),
	define.LinuxCheck("tainted", "Kernel tainted flags", model.AspectKernel,
		[]model.Probe{{Label: "tainted", Inv: model.Shell{Script: "cat /proc/sys/kernel/tainted 2>/dev/null"}}},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("kernel-tainted", `^[1-9]`, model.Medium,
					"tainted non-zero: kernel is tainted (bad unload/out-of-tree code; proprietary drivers set it too)"),
			},
		}),
	define.LinuxCheck("module-sig-config", "Kernel module signature config", model.AspectKernel,
		[]model.Probe{{Label: "zcat", Inv: model.Shell{Script: moduleSigScript}}},
		define.CheckOpt{
			Syntax: "env",
			Rules: []model.Rule{
				model.NewRule("module-sig-off", `^CONFIG_MODULE_SIG=(?:n|m)`, model.Medium, "module signing not enabled"),
				model.NewRule("module-sig-not-forced", `^CONFIG_MODULE_SIG_FORCE=n`, model.Medium,
					"unsigned modules still load (warned but not blocked)"),
			},
		}),
	// dmesg's module lines are the evidence surface for load activity; placed last,
	// before the big lsmod table
	define.LinuxCheck("dmesg", "Kernel module logs", model.AspectKernel,
		[]model.Probe{{Label: "dmesg", Inv: model.NewCommand("dmesg")}},
		define.CheckOpt{
			Syntax: "dmesg",
			// The keep filter leaves only module lines: load/taint records in the kernel ring
			// plus module-load activity logged by systemd (Inserted module etc., not in the
			// ring). Lines carrying a signal (taint) bypass the filter and are always kept.
			Filters: []model.LineFilter{
				model.NewFilter("dmesg-module", `(?i)module`, model.FilterKeep),
			},
			Rules: []model.Rule{
				model.NewRule("dmesg-taint", `(?i)\btaint`, model.Medium,
					"kernel tainted (out-of-tree/unsigned modules etc.)"),
			},
		}),
	// lsmod is a big all-modules table with little signal; placed at the end of the
	// aspect so it does not block the targeted checks before it
	define.LinuxCheck("lsmod", "Kernel modules", model.AspectKernel,
		[]model.Probe{
			{Label: "lsmod", Inv: model.NewCommand("lsmod")},
			{Label: "proc-modules", Inv: model.Shell{Script: "cat /proc/modules 2>/dev/null"}},
		},
		// The Used by tail can contain spaces, which the generic table word-by-word
		// coloring would split apart
		define.CheckOpt{Syntax: "lsmod"}),
}
