// tests for the in-process capability decoding: libcap's flag groupings and
// the xattr record's bit order.

package linux

import "testing"

// capBit is one capability's bit in the sets capsText takes.
func capBit(name string) uint {
	for i, candidate := range capNames {
		if candidate == name {
			return uint(i)
		}
	}
	return 0
}

func TestCapsTextMatchesGetcap(t *testing.T) {
	raw := uint64(1) << capBit("cap_net_raw")
	nice := uint64(1) << capBit("cap_sys_nice")
	bind := uint64(1) << capBit("cap_net_bind_service")
	admin := uint64(1) << capBit("cap_net_admin")
	cases := []struct {
		name                              string
		permitted, inheritable, effective uint64
		want                              string
	}{
		{"nothing", 0, 0, 0, ""},
		{"effective+permitted", raw, 0, raw, "cap_net_raw=ep"},
		{"permitted only", raw, 0, 0, "cap_net_raw=p"},
		{"inheritable only", 0, raw, 0, "cap_net_raw=i"},
		{"inheritable+permitted", raw, raw, 0, "cap_net_raw=ip"},
		{"all three", raw, raw, raw, "cap_net_raw=eip"},
		// the corpus this decoder was checked against on the host: three caps
		// in one group, ascending bit order
		{"three caps", bind | admin | nice, 0, bind | admin | nice,
			"cap_net_bind_service,cap_net_admin,cap_sys_nice=ep"},
		// different flag strings split the line into two groups
		{"two groups", raw | nice, 0, raw, "cap_net_raw=ep cap_sys_nice=p"},
		// a capability past the known table keeps its number
		{"unknown bit", 1 << 45, 0, 1 << 45, "cap_45=ep"},
	}
	for _, c := range cases {
		if got := capsText(c.permitted, c.inheritable, c.effective); got != c.want {
			t.Errorf("%s: capsText = %q, want %q", c.name, got, c.want)
		}
	}
}
