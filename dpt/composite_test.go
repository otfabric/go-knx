// SPDX-License-Identifier: MIT

package dpt

import (
	"bytes"
	"errors"
	"testing"

	"github.com/otfabric/go-knx"
)

// The vectors below are worked out by hand from the field layouts; they
// are not taken from the specification or another implementation.

func TestFanStageAndChangeover(t *testing.T) {
	if b := enc(t, "5.100", 3); !bytes.Equal(b, hx("03")) {
		t.Errorf("5.100 = % X", b)
	}
	if v := dec(t, "5.100", hx("ff")); v != uint64(255) {
		t.Errorf("5.100 decode = %v", v)
	}
	_, err := MustLookup("5.100").Encode(256)
	wantInvalid(t, "5.100 256", err)

	ty := MustLookup("20.107")
	if v := dec(t, "20.107", hx("01")); v != (Enum{Value: 1, Name: "cooling only"}) {
		t.Errorf("20.107 decode = %v", v)
	}
	if b := enc(t, "20.107", "heating only"); !bytes.Equal(b, hx("02")) {
		t.Errorf("20.107 = % X", b)
	}
	_, err = ty.Decode(hx("03"))
	wantInvalid(t, "20.107 3", err)
}

func TestAccessData(t *testing.T) {
	ty := MustLookup("15.000")
	if ty.Name != "DPT_Access_Data" || ty.Size() != 4 {
		t.Fatalf("15.000 = %+v", ty)
	}
	for _, c := range []struct {
		v   AccessData
		hex string
	}{
		{AccessData{Code: 123456, Permission: true, Index: 3}, "12345643"},
		{AccessData{Code: 42, Error: true, RightToLeft: true, Encrypted: true}, "000042b0"},
		{AccessData{Code: 900001, Index: 15}, "9000010f"},
	} {
		if b := enc(t, "15.000", c.v); !bytes.Equal(b, hx(c.hex)) {
			t.Errorf("Encode(%v) = % X, want %s", c.v, b, c.hex)
		}
		if v := dec(t, "15.000", hx(c.hex)); v != c.v {
			t.Errorf("Decode(%s) = %#v", c.hex, v)
		}
	}
	// A nibble above 9 in any of the six digits.
	for _, h := range []string{"a0000000", "0a000000", "00f00000", "000b0000", "0000c000", "00000d00"} {
		_, err := ty.Decode(hx(h))
		wantInvalid(t, "15.000 "+h, err)
	}
	for _, v := range []any{AccessData{Code: 1000000}, AccessData{Index: 16}, uint32(5)} {
		_, err := ty.Encode(v)
		wantInvalid(t, "15.000 encode", err)
	}

	a := AccessData{Code: 42, Error: true, Permission: true, RightToLeft: true, Encrypted: true, Index: 7}
	if s := ty.Format(a); s != "000042 index=7 error permission right-to-left encrypted" {
		t.Errorf("Format = %q", s)
	}
	if v, err := ty.Parse("000042 index=7 Error permission right-to-left encrypted"); err != nil || v != a {
		t.Errorf("Parse = %#v, %v", v, err)
	}
	if v, err := ty.Parse("7"); err != nil || v != (AccessData{Code: 7}) {
		t.Errorf("Parse(7) = %#v, %v", v, err)
	}
	for _, in := range []string{"", "1234567", "12 index=16", "12 index=x", "12 open", "abc"} {
		if _, err := ty.Parse(in); !errors.Is(err, knx.ErrInvalidValue) {
			t.Errorf("Parse(%q): %v", in, err)
		}
	}
}

func TestBitSetSubtypes(t *testing.T) {
	for _, id := range []string{"21.002", "21.100", "21.101", "21.102", "21.103", "21.104", "21.105", "21.106",
		"21.601", "21.1000", "21.1001", "21.1010", "21.1200", "21.1201"} {
		if b := enc(t, id, 0x81); !bytes.Equal(b, hx("81")) {
			t.Errorf("%s = % X", id, b)
		}
		_, err := MustLookup(id).Encode(256)
		wantInvalid(t, id+" 256", err)
	}
	for _, id := range []string{"22.100", "22.101", "22.103", "22.1000", "22.1010"} {
		if b := enc(t, id, 0x8001); !bytes.Equal(b, hx("8001")) {
			t.Errorf("%s = % X", id, b)
		}
		if v := dec(t, id, hx("0036")); v != uint64(0x36) {
			t.Errorf("%s decode = %v", id, v)
		}
		if s := MustLookup(id).Format(uint64(0x36)); s != "0b0000000000110110" {
			t.Errorf("%s Format = %q", id, s)
		}
	}
}

func TestOnOffInfo(t *testing.T) {
	ty := MustLookup("27.001")
	o := OnOffInfo{Valid: 0x0005, On: 0x0001}
	if b := enc(t, "27.001", o); !bytes.Equal(b, hx("00050001")) {
		t.Errorf("Encode = % X", b)
	}
	if v := dec(t, "27.001", hx("8000ffff")); v != (OnOffInfo{Valid: 0x8000, On: 0xFFFF}) {
		t.Errorf("Decode = %#v", v)
	}
	if s := ty.Format(o); s != "valid=0x0005 on=0x0001" {
		t.Errorf("Format = %q", s)
	}
	for _, in := range []string{"valid=0x0005 on=0x0001", "5,1", "0b101, 0x1"} {
		if v, err := ty.Parse(in); err != nil || v != o {
			t.Errorf("Parse(%q) = %#v, %v", in, v, err)
		}
	}
	for _, in := range []string{"5", "5,1,1", "65536,0", "x,1"} {
		if _, err := ty.Parse(in); !errors.Is(err, knx.ErrInvalidValue) {
			t.Errorf("Parse(%q): %v", in, err)
		}
	}
	_, err := ty.Encode(uint32(5))
	wantInvalid(t, "27.001 uint32", err)
}

func TestVersion(t *testing.T) {
	ty := MustLookup("217.001")
	for _, c := range []struct {
		v   Version
		hex string
	}{
		{Version{Magic: 1, Version: 2, Revision: 3}, "0883"},
		{Version{Version: 1}, "0040"},
		{Version{Magic: 31, Version: 31, Revision: 63}, "ffff"},
	} {
		if b := enc(t, "217.001", c.v); !bytes.Equal(b, hx(c.hex)) {
			t.Errorf("Encode(%v) = % X, want %s", c.v, b, c.hex)
		}
		if v := dec(t, "217.001", hx(c.hex)); v != c.v {
			t.Errorf("Decode(%s) = %#v", c.hex, v)
		}
	}
	for _, v := range []any{Version{Magic: 32}, Version{Version: 32}, Version{Revision: 64}, "1.2.3"} {
		_, err := ty.Encode(v)
		wantInvalid(t, "217.001 encode", err)
	}
	if s := ty.Format(Version{1, 2, 3}); s != "1.2.3" {
		t.Errorf("Format = %q", s)
	}
	for _, in := range []string{"1.2", "32.0.0", "0.32.0", "0.0.64", "a.b.c"} {
		if _, err := ty.Parse(in); !errors.Is(err, knx.ErrInvalidValue) {
			t.Errorf("Parse(%q): %v", in, err)
		}
	}
}

func TestRoomSetpoints(t *testing.T) {
	// 21 °C: 2100 does not fit the 12-bit mantissa, so exponent 1 and
	// mantissa 1050 (0x41A); 19 °C and 17 °C fit at exponent 0; 7 °C is 700.
	for _, c := range []struct {
		id  string
		v   RoomSetpoints
		hex string
	}{
		{"222.100", RoomSetpoints{Comfort: 21, Standby: 19, Economy: 17}, "0c1a076c06a4"},
		{"222.101", RoomSetpoints{Comfort: -1, Economy: 0.5}, "879c00000032"},
		{"275.100", RoomSetpoints{Comfort: 21, Standby: 19, Economy: 17, Protection: 7}, "0c1a076c06a402bc"},
		{"275.101", RoomSetpoints{Protection: -1}, "000000000000879c"},
	} {
		if b := enc(t, c.id, c.v); !bytes.Equal(b, hx(c.hex)) {
			t.Errorf("%s Encode(%v) = % X, want %s", c.id, c.v, b, c.hex)
		}
		if v := dec(t, c.id, hx(c.hex)); v != c.v {
			t.Errorf("%s Decode(%s) = %#v", c.id, c.hex, v)
		}
	}
	for id, v := range map[string]any{
		"222.100": RoomSetpoints{Comfort: -274},
		"222.101": RoomSetpoints{Protection: 1},
		"275.100": RoomSetpoints{Protection: -300},
		"275.101": RoomSetpoints{Standby: 700000},
		"222":     21.5,
	} {
		_, err := MustLookup(id).Encode(v)
		wantInvalid(t, id+" encode", err)
	}
	for id, h := range map[string]string{"222.100": "7fff00000000", "222.101": "000000007fff", "275.101": "0000000000007fff"} {
		_, err := MustLookup(id).Decode(hx(h))
		if !errors.Is(err, ErrFloat16Invalid) {
			t.Errorf("%s Decode(%s): %v, want ErrFloat16Invalid", id, h, err)
		}
	}

	ty := MustLookup("222.100")
	r := RoomSetpoints{Comfort: 21, Standby: 19, Economy: 17}
	if s := ty.Format(r); s != "comfort=21 standby=19 economy=17 °C" {
		t.Errorf("Format = %q", s)
	}
	for _, in := range []string{"comfort=21 standby=19 economy=17 °C", "21,19,17", "21, 19, 17 °C"} {
		if v, err := ty.Parse(in); err != nil || v != r {
			t.Errorf("Parse(%q) = %#v, %v", in, v, err)
		}
	}
	for _, in := range []string{"21,19", "21,19,17,7", "a,b,c", "standby=19 comfort=21 economy=17", "comfort=21 standby=19 economy=17 protection=7"} {
		if _, err := ty.Parse(in); !errors.Is(err, knx.ErrInvalidValue) {
			t.Errorf("Parse(%q): %v", in, err)
		}
	}
	p := MustLookup("275.101")
	if s := p.Format(RoomSetpoints{Comfort: 1, Standby: -1, Economy: -2, Protection: -5}); s != "comfort=1 standby=-1 economy=-2 protection=-5 K" {
		t.Errorf("275.101 Format = %q", s)
	}
	// Another value type is formatted the generic way.
	if s := ty.Format(21.5); s != "21.5 °C" {
		t.Errorf("Format(float64) = %q", s)
	}
	// The main type has no range: a value beyond the 2-octet float fails
	// in its encoding.
	if _, err := MustLookup("222").Encode(RoomSetpoints{Comfort: 1e9}); !errors.Is(err, knx.ErrInvalidValue) {
		t.Errorf("222 Encode(1e9): %v", err)
	}
	if s := (RoomSetpoints{Comfort: 21, Standby: 19, Economy: 17}).String(); s != "comfort=21 standby=19 economy=17 protection=0" {
		t.Errorf("String = %q", s)
	}
}

func TestAlpha2Codes(t *testing.T) {
	for _, c := range []struct{ id, v, hex string }{{"234.001", "de", "6465"}, {"234.002", "NL", "4e4c"}} {
		if b := enc(t, c.id, c.v); !bytes.Equal(b, hx(c.hex)) {
			t.Errorf("%s Encode(%q) = % X", c.id, c.v, b)
		}
		if v := dec(t, c.id, hx(c.hex)); v != c.v {
			t.Errorf("%s Decode = %v", c.id, v)
		}
	}
	ty := MustLookup("234.001")
	for _, v := range []any{"d", "dee", "d1", "", 5} {
		_, err := ty.Encode(v)
		wantInvalid(t, "234.001 encode", err)
	}
	for _, h := range []string{"6400", "3132", "6440", "5b61"} {
		_, err := ty.Decode(hx(h))
		wantInvalid(t, "234.001 "+h, err)
	}
	if s := ty.Format("en"); s != `"en"` {
		t.Errorf("Format = %q", s)
	}
	if v, err := ty.Parse(`"en"`); err != nil || v != "en" {
		t.Errorf("Parse = %v, %v", v, err)
	}
}

func TestCompositeKindStrings(t *testing.T) {
	for k, want := range map[Kind]string{KindAccess: "access", KindOnOffInfo: "onoff-info", KindVersion: "version", KindSetpoints: "setpoints"} {
		if k.String() != want {
			t.Errorf("%d.String() = %q", int(k), k.String())
		}
	}
	if s := (AccessData{Code: 5}).String(); s != "000005 index=0" {
		t.Errorf("AccessData.String = %q", s)
	}
}
