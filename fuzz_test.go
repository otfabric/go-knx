// SPDX-License-Identifier: MIT

package knx

import "testing"

// FuzzParseGroupAddress checks that ParseGroupAddressWithFormat never
// panics and that an accepted address formats back to its input exactly
// (parsing is strict, so it is reversible).
func FuzzParseGroupAddress(f *testing.F) {
	for _, s := range []string{"1/2/3", "31/7/255", "1/515", "31/2047", "2563", "65535", "0", "01/2/3", "32/0/0", "1/2/3/4", " 1/2/3", "-1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		g, format, err := ParseGroupAddressWithFormat(s)
		if err != nil {
			return
		}
		if got := g.Format(format); got != s {
			t.Fatalf("%q parsed as %04X (%v), formats as %q", s, uint16(g), format, got)
		}
		if g2, err := ParseGroupAddress(s); err != nil || g2 != g {
			t.Fatalf("ParseGroupAddress(%q) = %v, %v", s, g2, err)
		}
	})
}

// FuzzParseIndividualAddress checks that ParseIndividualAddress never
// panics and that an accepted address formats back to its input exactly.
func FuzzParseIndividualAddress(f *testing.F) {
	for _, s := range []string{"1.1.10", "15.15.255", "0.0.0", "16.0.0", "01.1.1", "1.1", "+1.1.1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, err := ParseIndividualAddress(s)
		if err != nil {
			return
		}
		if a.String() != s {
			t.Fatalf("%q parsed as %04X, formats as %q", s, uint16(a), a.String())
		}
	})
}
