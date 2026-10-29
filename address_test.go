// SPDX-License-Identifier: MIT

package knx

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestParseIndividualAddress(t *testing.T) {
	ok := []struct {
		in                 string
		area, line, device uint8
		raw                uint16
	}{
		{"0.0.0", 0, 0, 0, 0x0000},
		{"1.1.10", 1, 1, 10, 0x110A},
		{"15.15.255", 15, 15, 255, 0xFFFF},
		{"1.0.0", 1, 0, 0, 0x1000},
		{"0.15.0", 0, 15, 0, 0x0F00},
	}
	for _, c := range ok {
		a, err := ParseIndividualAddress(c.in)
		if err != nil {
			t.Fatalf("%q: %v", c.in, err)
		}
		if a.Area() != c.area || a.Line() != c.line || a.Device() != c.device || a.Uint16() != c.raw {
			t.Errorf("%q = %d.%d.%d (%04X)", c.in, a.Area(), a.Line(), a.Device(), a.Uint16())
		}
		if a.String() != c.in {
			t.Errorf("%q formats as %q", c.in, a.String())
		}
		n, err := NewIndividualAddress(c.area, c.line, c.device)
		if err != nil || n != a {
			t.Errorf("NewIndividualAddress(%d,%d,%d) = %v, %v", c.area, c.line, c.device, n, err)
		}
	}
	bad := []string{
		"", "1", "1.1", "1.1.1.1", "1..1", ".1.1", "1.1.",
		"16.0.0", "0.16.0", "0.0.256", "99999.0.0", "100000.0.0",
		"01.1.1", "1.01.1", "1.1.01", "00.0.0", // leading zeros
		" 1.1.1", "1.1.1 ", "1. 1.1", // spaces
		"+1.1.1", "-1.1.1", "1.-1.1", // signs
		"0x1.1.1", "a.b.c", "1/1/1", "1.1.1\n", "１.1.1",
	}
	for _, s := range bad {
		if a, err := ParseIndividualAddress(s); !errors.Is(err, ErrInvalidAddress) {
			t.Errorf("ParseIndividualAddress(%q) = %v, %v; want ErrInvalidAddress", s, a, err)
		}
	}
	for _, c := range []struct{ a, l uint8 }{{16, 0}, {0, 16}, {255, 255}} {
		if _, err := NewIndividualAddress(c.a, c.l, 0); !errors.Is(err, ErrInvalidAddress) {
			t.Errorf("NewIndividualAddress(%d,%d,0): %v", c.a, c.l, err)
		}
	}
}

func TestParseGroupAddress(t *testing.T) {
	ok := []struct {
		in     string
		raw    uint16
		format GroupAddressFormat
	}{
		{"0/0/0", 0x0000, GroupThreeLevel},
		{"1/2/3", 0x0A03, GroupThreeLevel},
		{"31/7/255", 0xFFFF, GroupThreeLevel},
		{"0/0", 0x0000, GroupTwoLevel},
		{"1/515", 0x0A03, GroupTwoLevel},
		{"31/2047", 0xFFFF, GroupTwoLevel},
		{"0", 0x0000, GroupFree},
		{"2563", 0x0A03, GroupFree},
		{"65535", 0xFFFF, GroupFree},
	}
	for _, c := range ok {
		g, f, err := ParseGroupAddressWithFormat(c.in)
		if err != nil || g.Uint16() != c.raw || f != c.format {
			t.Errorf("%q = %04X %v, %v; want %04X %v", c.in, g.Uint16(), f, err, c.raw, c.format)
			continue
		}
		if g.Format(f) != c.in {
			t.Errorf("%q formats back as %q", c.in, g.Format(f))
		}
		if g2, err := ParseGroupAddress(c.in); err != nil || g2 != g {
			t.Errorf("ParseGroupAddress(%q) = %v, %v", c.in, g2, err)
		}
	}
	g := MustParseGroupAddress("1/2/3")
	if g.Main() != 1 || g.Middle() != 2 || g.Sub() != 3 || g.Sub2() != 515 || g.String() != "1/2/3" {
		t.Errorf("accessors of 1/2/3: %d %d %d %d %q", g.Main(), g.Middle(), g.Sub(), g.Sub2(), g.String())
	}
	if got := g.Format(GroupAddressFormat(9)); got != "1/2/3" {
		t.Errorf("unknown format falls back to %q", got)
	}
	bad := []string{
		"", "/", "1/", "/1", "1//3", "1/2/3/4",
		"32/0/0", "0/8/0", "0/0/256", "32/0", "0/2048", "65536", "99999", "100000",
		"01/2/3", "1/02/3", "1/2/03", "01/1", "1/01", "01", "00",
		" 1/2/3", "1/2/3 ", "1 /2/3",
		"+1/2/3", "-1/2/3", "1/-2", "-1",
		"1.2.3", "0x10", "1/2/x",
	}
	for _, s := range bad {
		if g, err := ParseGroupAddress(s); !errors.Is(err, ErrInvalidAddress) {
			t.Errorf("ParseGroupAddress(%q) = %v, %v; want ErrInvalidAddress", s, g, err)
		}
	}
}

func TestNewGroupAddress(t *testing.T) {
	if g, err := NewGroupAddress3(31, 7, 255); err != nil || g != 0xFFFF {
		t.Errorf("NewGroupAddress3 max = %v, %v", g, err)
	}
	if g, err := NewGroupAddress2(31, 2047); err != nil || g != 0xFFFF {
		t.Errorf("NewGroupAddress2 max = %v, %v", g, err)
	}
	for _, c := range []struct{ m, mid uint8 }{{32, 0}, {0, 8}} {
		if _, err := NewGroupAddress3(c.m, c.mid, 0); !errors.Is(err, ErrInvalidAddress) {
			t.Errorf("NewGroupAddress3(%d,%d,0): %v", c.m, c.mid, err)
		}
	}
	for _, c := range []struct {
		m   uint8
		sub uint16
	}{{32, 0}, {0, 2048}} {
		if _, err := NewGroupAddress2(c.m, c.sub); !errors.Is(err, ErrInvalidAddress) {
			t.Errorf("NewGroupAddress2(%d,%d): %v", c.m, c.sub, err)
		}
	}
}

func TestGroupAddressFormat(t *testing.T) {
	for in, want := range map[string]GroupAddressFormat{
		"3-level": GroupThreeLevel, "3": GroupThreeLevel, "THREE": GroupThreeLevel, "three-level": GroupThreeLevel,
		"2-level": GroupTwoLevel, "2": GroupTwoLevel, "Two": GroupTwoLevel, "two-level": GroupTwoLevel,
		"free": GroupFree, "1": GroupFree, "1-level": GroupFree,
	} {
		f, err := ParseGroupAddressFormat(in)
		if err != nil || f != want {
			t.Errorf("ParseGroupAddressFormat(%q) = %v, %v", in, f, err)
		}
	}
	if _, err := ParseGroupAddressFormat("4-level"); !errors.Is(err, ErrInvalidAddress) {
		t.Errorf("4-level: %v", err)
	}
	for f, want := range map[GroupAddressFormat]string{GroupThreeLevel: "3-level", GroupTwoLevel: "2-level", GroupFree: "free", 7: "GroupAddressFormat(7)"} {
		if f.String() != want {
			t.Errorf("%d.String() = %q", int(f), f.String())
		}
		if int(f) < 3 {
			if back, err := ParseGroupAddressFormat(f.String()); err != nil || back != f {
				t.Errorf("String/Parse round trip of %v", f)
			}
		}
	}
}

// TestAllAddressesRoundTrip formats every 16-bit value in every
// presentation and parses it back.
func TestAllAddressesRoundTrip(t *testing.T) {
	for v := 0; v <= 0xFFFF; v++ {
		ia := IndividualAddress(v)
		if back, err := ParseIndividualAddress(ia.String()); err != nil || back != ia {
			t.Fatalf("individual %04X: %q → %v, %v", v, ia.String(), back, err)
		}
		g := GroupAddress(v)
		for _, f := range []GroupAddressFormat{GroupThreeLevel, GroupTwoLevel, GroupFree} {
			s := g.Format(f)
			back, bf, err := ParseGroupAddressWithFormat(s)
			if err != nil || back != g || bf != f {
				t.Fatalf("group %04X %v: %q → %v %v, %v", v, f, s, back, bf, err)
			}
		}
	}
}

func TestAddressText(t *testing.T) {
	type doc struct {
		Src IndividualAddress `json:"src"`
		Dst GroupAddress      `json:"dst"`
	}
	b, err := json.Marshal(doc{Src: MustParseIndividualAddress("1.1.10"), Dst: MustParseGroupAddress("1/515")})
	if err != nil || string(b) != `{"src":"1.1.10","dst":"1/2/3"}` {
		t.Fatalf("Marshal = %s, %v", b, err)
	}
	var d doc
	if err := json.Unmarshal([]byte(`{"src":"15.15.255","dst":"2563"}`), &d); err != nil || d.Src != 0xFFFF || d.Dst != 0x0A03 {
		t.Fatalf("Unmarshal = %+v, %v", d, err)
	}
	if err := json.Unmarshal([]byte(`{"src":"16.0.0"}`), &d); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("Unmarshal bad individual: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"dst":"32/0/0"}`), &d); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("Unmarshal bad group: %v", err)
	}
	if d.Src != 0xFFFF || d.Dst != 0x0A03 {
		t.Fatalf("failed Unmarshal modified the value: %+v", d)
	}
}

func TestMustParsePanics(t *testing.T) {
	for name, fn := range map[string]func(){
		"individual": func() { MustParseIndividualAddress("1.1") },
		"group":      func() { MustParseGroupAddress("1/2/3/4") },
	} {
		func() {
			defer func() {
				r := recover()
				if err, ok := r.(error); !ok || !errors.Is(err, ErrInvalidAddress) {
					t.Errorf("%s: recovered %v", name, r)
				}
			}()
			fn()
		}()
	}
}

func TestPriority(t *testing.T) {
	for p, s := range map[Priority]string{PrioritySystem: "system", PriorityNormal: "normal", PriorityUrgent: "urgent", PriorityLow: "low"} {
		if p.String() != s {
			t.Errorf("%d.String() = %q", p, p.String())
		}
		for _, in := range []string{s, string([]rune(s)[0]-32) + s[1:]} {
			got, err := ParsePriority(in)
			if err != nil || got != p {
				t.Errorf("ParsePriority(%q) = %v, %v", in, got, err)
			}
		}
	}
	if Priority(4).String() != "Priority(4)" {
		t.Errorf("Priority(4).String() = %q", Priority(4).String())
	}
	for _, s := range []string{"", "high", "Priority(4)", "1"} {
		if _, err := ParsePriority(s); !errors.Is(err, ErrInvalidOption) {
			t.Errorf("ParsePriority(%q): %v", s, err)
		}
	}
}
