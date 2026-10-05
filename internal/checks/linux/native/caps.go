// The capability text spellings shared by the in-process tier and its tests:
// libcap's cap_to_text shape, which is also what the rules grade.

package native

import (
	"fmt"
	"karma/internal/model"
	"regexp"
	"strconv"
	"strings"
)

// capsText spells the three capability sets the way libcap's cap_to_text does:
// caps that share a flag string form one comma-separated group in ascending bit
// order, groups are separated by a blank, and the flag letters always come in
// e/i/p order (observed from getcap: "=ep", "=eip").
func capsText(permitted, inheritable, effective uint64) string {
	var (
		groups []string
		names  []string
		flags  string
	)
	flush := func() {
		if len(names) > 0 {
			groups = append(groups, strings.Join(names, ",")+"="+flags)
			names = nil
		}
	}
	for bit := 0; bit < 64; bit++ {
		mask := uint64(1) << bit
		if permitted&mask|inheritable&mask|effective&mask == 0 {
			continue
		}
		current := ""
		if effective&mask != 0 {
			current += "e"
		}
		if inheritable&mask != 0 {
			current += "i"
		}
		if permitted&mask != 0 {
			current += "p"
		}
		if len(names) > 0 && current != flags {
			flush()
		}
		flags = current
		names = append(names, capName(bit))
	}
	flush()
	return strings.Join(groups, " ")
}

// capName is the capability's kernel spelling for one bit; a bit past the known
// table prints its number, the way a newer kernel's capabilities decode.
func capName(bit int) string {
	if bit < len(capNames) {
		return capNames[bit]
	}
	return fmt.Sprintf("cap_%d", bit)
}

// capNames is the Linux capability list by bit number (uapi/linux/capability.h).
// A newer kernel's bits past the table decode to their number instead of
// garbage, and a missing capsh never blocks the check.
var capNames = []string{
	"cap_chown", "cap_dac_override", "cap_dac_read_search", "cap_fowner",
	"cap_fsetid", "cap_kill", "cap_setgid", "cap_setuid", "cap_setpcap",
	"cap_linux_immutable", "cap_net_bind_service", "cap_net_broadcast",
	"cap_net_admin", "cap_net_raw", "cap_ipc_lock", "cap_ipc_owner",
	"cap_sys_module", "cap_sys_rawio", "cap_sys_chroot", "cap_sys_ptrace",
	"cap_sys_pacct", "cap_sys_admin", "cap_sys_boot", "cap_sys_nice",
	"cap_sys_resource", "cap_sys_time", "cap_sys_tty_config", "cap_mknod",
	"cap_lease", "cap_audit_write", "cap_audit_control", "cap_setfcap",
	"cap_mac_override", "cap_mac_admin", "cap_syslog", "cap_wake_alarm",
	"cap_block_suspend", "cap_audit_read", "cap_perfmon", "cap_bpf",
	"cap_checkpoint_restore",
}

// capMaskLine matches one /proc/self/status capability line: a Cap* key and a
// hex mask (kallsyms-style leading zeros included).
var capMaskLine = regexp.MustCompile(`^(Cap\w+:[ \t]+)([0-9a-fA-F]{8,16})[ \t]*$`)

// DecodeCapMasks is the Adapt of the /proc/self/status tier: it appends the
// decoded capability names to each non-zero mask line, so that tier and the
// check's capsh tier read as names and the same rules light on either. A body
// with no set mask is returned as is.
func DecodeCapMasks(_ string, body string) *model.Shaped {
	lines := strings.Split(body, "\n")
	changed := false
	for i, line := range lines {
		m := capMaskLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		value, err := strconv.ParseUint(m[2], 16, 64)
		if err != nil {
			continue
		}
		names := capBitNames(value)
		if len(names) == 0 {
			continue
		}
		lines[i] = fmt.Sprintf("%s%s  = %s", m[1], m[2], strings.Join(names, ", "))
		changed = true
	}
	if !changed {
		return nil
	}
	return &model.Shaped{Text: strings.Join(lines, "\n")}
}

// capBitNames decodes one mask into capability names, lowest bit first.
func capBitNames(mask uint64) []string {
	var names []string
	for bit := 0; mask>>bit != 0; bit++ {
		if mask>>bit&1 == 0 {
			continue
		}
		if bit < len(capNames) {
			names = append(names, capNames[bit])
		} else {
			names = append(names, fmt.Sprintf("bit%d", bit))
		}
	}
	return names
}
