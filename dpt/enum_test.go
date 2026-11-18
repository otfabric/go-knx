// SPDX-License-Identifier: MIT

package dpt

import (
	"bytes"
	"strings"
	"testing"
)

// The vectors below are worked out by hand from the field layouts; they
// are not taken from the specification or another implementation.

func TestEnumSubtypes(t *testing.T) {
	for _, c := range []struct {
		id  string
		hex string
		v   Enum
	}{
		{"20.001", "02", Enum{2, "master"}},
		{"20.004", "03", Enum{3, "void"}},
		{"20.006", "32", Enum{50, "shutters and blinds"}},
		{"20.011", "12", Enum{18, "group object type too long"}},
		{"20.013", "0b", Enum{11, "1.25 min"}},
		{"20.014", "0c", Enum{12, "hurricane"}},
		{"20.021", "06", Enum{6, "6 oktas"}},
		{"20.101", "03", Enum{3, "modulating"}},
		{"20.109", "04", Enum{4, "extract air (4)"}},
		{"20.114", "ff", Enum{255, "void device type"}},
		{"20.116", "03", Enum{3, "enable both stages"}},
		{"20.602", "0f", Enum{15, "90.5 s"}},
		{"20.610", "ff", Enum{255, "detection not possible or error (255)"}},
		{"20.1000", "06", Enum{6, "cEMI transport layer"}},
		{"20.1221", "06", Enum{6, "no error"}},
		{"23.001", "03", Enum{3, "on/off"}},
		{"23.002", "02", Enum{2, "alarm position down"}},
		{"23.003", "01", Enum{1, "down"}},
		{"23.102", "03", Enum{3, "building protection/auto"}},
	} {
		if v := dec(t, c.id, hx(c.hex)); v != c.v {
			t.Errorf("%s Decode(%s) = %#v, want %#v", c.id, c.hex, v, c.v)
		}
		for _, in := range []any{c.v, c.v.Name, strings.ToUpper(c.v.Name), int(c.v.Value)} {
			if b := enc(t, c.id, in); !bytes.Equal(b, hx(c.hex)) {
				t.Errorf("%s Encode(%#v) = % X, want %s", c.id, in, b, c.hex)
			}
		}
	}
	// Values the subtype does not define, and the reserved ones left out.
	for _, c := range []struct{ id, hex string }{
		{"20.004", "04"}, {"20.007", "00"}, {"20.101", "00"}, {"20.109", "05"}, {"20.114", "09"}, {"20.115", "03"},
		{"20.609", "ff"}, {"20.1219", "05"}, {"20.1220", "07"}, {"23.002", "03"},
		{"23.001", "04"}, {"23", "04"}, // more bits than the type
	} {
		_, err := MustLookup(c.id).Decode(hx(c.hex))
		wantInvalid(t, c.id+" "+c.hex, err)
	}
	for _, c := range []struct {
		id string
		v  any
	}{{"20.004", 4}, {"20.004", "none"}, {"23.002", 3}, {"23", 4}, {"23", Enum{Value: 255}}} {
		_, err := MustLookup(c.id).Encode(c.v)
		wantInvalid(t, c.id, err)
	}
	if b := enc(t, "23", 3); !bytes.Equal(b, hx("03")) {
		t.Errorf("main 23 Encode(3) = % X", b)
	}
	if ty := MustLookup("23.001"); !ty.Small() || ty.Size() != 1 || ty.Bits != 2 {
		t.Errorf("23.001: Small %v Size %d Bits %d", ty.Small(), ty.Size(), ty.Bits)
	}
}

// TestEnumNamesUnique checks that no two values of an enumeration share a
// name, so that every name parses to one value.
func TestEnumNamesUnique(t *testing.T) {
	for _, ty := range All() {
		seen := map[string]uint8{}
		for k, n := range ty.Enum {
			if n == "" {
				t.Errorf("%s: value %d has no name", ty, k)
			}
			if p, dup := seen[strings.ToLower(n)]; dup {
				t.Errorf("%s: values %d and %d are both named %q", ty, p, k, n)
			}
			seen[strings.ToLower(n)] = k
		}
	}
}
