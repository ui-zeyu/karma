package linux

import (
	"strings"
	"testing"
)

// decodeCapMasks is the /proc/self/status tier's Adapt: set masks gain decoded
// names, zero masks and non-Cap lines stay untouched, and a body with nothing
// to decode returns nil so the raw text is used.
func TestDecodeCapMasks(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string // fragments every decoded line must carry
		same bool     // the body must come back unchanged (nil Shaped)
	}{
		{
			name: "single cap",
			body: "CapInh:\t0000000000000000\nCapEff:\t0000000000000001\n",
			want: []string{"CapEff:\t0000000000000001  = cap_chown"},
		},
		{
			name: "full root mask names the dangerous caps",
			body: "CapEff:\t000001ffffffffff\n",
			want: []string{"cap_sys_admin", "cap_sys_module", "cap_dac_read_search", "cap_sys_ptrace"},
		},
		{
			name: "unknown high bits decode to their number",
			body: "CapBnd: 0000200000000000\n",
			want: []string{"bit45"},
		},
		{
			name: "all zero stays raw",
			body: "CapInh:\t0000000000000000\nCapAmb:\t0000000000000000\n",
			same: true,
		},
		{
			name: "non-cap lines stay raw",
			body: "context: container\nSeccomp:\t2\n",
			same: true,
		},
	}
	for _, tc := range cases {
		shaped := decodeCapMasks("", tc.body)
		if tc.same {
			if shaped != nil {
				t.Errorf("%s: wanted nil Shaped, got %q", tc.name, shaped.Text)
			}
			continue
		}
		if shaped == nil {
			t.Errorf("%s: wanted decoding, got nil", tc.name)
			continue
		}
		for _, want := range tc.want {
			if !strings.Contains(shaped.Text, want) {
				t.Errorf("%s: decoded text misses %q:\n%s", tc.name, want, shaped.Text)
			}
		}
	}
}

// capBitNames walks the mask lowest bit first; a quick cross-check that bit 21
// is cap_sys_admin and bits past the table fall back to numbers.
func TestCapBitNames(t *testing.T) {
	names := capBitNames(1 << 21)
	if len(names) != 1 || names[0] != "cap_sys_admin" {
		t.Errorf("bit 21 should be cap_sys_admin, got %v", names)
	}
	names = capBitNames(1<<40 | 1<<42)
	if len(names) != 2 || names[0] != "cap_checkpoint_restore" || names[1] != "bit42" {
		t.Errorf("past-table bits should number themselves, got %v", names)
	}
}
