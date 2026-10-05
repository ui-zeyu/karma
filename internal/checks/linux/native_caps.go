// The capability text spellings shared by the in-process tier and its tests:
// libcap's cap_to_text shape, which is also what the rules grade.

package linux

import (
	"fmt"
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
