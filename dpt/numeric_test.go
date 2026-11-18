// SPDX-License-Identifier: MIT

package dpt

import (
	"bytes"
	"testing"
)

// The vectors below are worked out by hand from the field layouts; they
// are not taken from the specification or another implementation.

func TestCoefficientAndVolumeSubtypes(t *testing.T) {
	// 9.031: 0.5 is mantissa 50, exponent 0.
	if b := enc(t, "9.031", 0.5); !bytes.Equal(b, hx("0032")) {
		t.Errorf("9.031 = % X", b)
	}
	if v := dec(t, "9.031", hx("0032")); v != 0.5 {
		t.Errorf("9.031 decode = %v", v)
	}
	_, err := MustLookup("9.031").Encode(-0.01)
	wantInvalid(t, "9.031 negative", err)

	for _, id := range []string{"13.1200", "13.1201"} {
		if b := enc(t, id, -2); !bytes.Equal(b, hx("fffffffe")) {
			t.Errorf("%s = % X", id, b)
		}
		if v := dec(t, id, hx("80000000")); v != int64(-2147483648) {
			t.Errorf("%s decode = %v", id, v)
		}
		_, err := MustLookup(id).Encode(int64(1) << 31)
		wantInvalid(t, id+" 2^31", err)
	}
	if s := MustLookup("13.1201").Format(int64(-3)); s != "-3 m³" {
		t.Errorf("13.1201 Format = %q", s)
	}

	for _, id := range []string{"14.1200", "14.1201"} {
		if b := enc(t, id, 1.5); !bytes.Equal(b, hx("3fc00000")) {
			t.Errorf("%s = % X", id, b)
		}
		if v := dec(t, id, hx("c0200000")); v != -2.5 {
			t.Errorf("%s decode = %v", id, v)
		}
		_, err := MustLookup(id).Decode(hx("7fc00000"))
		wantInvalid(t, id+" NaN", err)
	}
	if s := MustLookup("14.1201").Format(2.5); s != "2.5 l/s" {
		t.Errorf("14.1201 Format = %q", s)
	}
}

func TestChannelActivation24(t *testing.T) {
	ty := MustLookup("30.1010")
	if ty.Size() != 3 || ty.Small() {
		t.Fatalf("30.1010: Size %d Small %v", ty.Size(), ty.Small())
	}
	if b := enc(t, "30.1010", 0x800001); !bytes.Equal(b, hx("800001")) {
		t.Errorf("Encode = % X", b)
	}
	if v := dec(t, "30.1010", hx("ffffff")); v != uint64(0xFFFFFF) {
		t.Errorf("Decode = %v", v)
	}
	for _, v := range []any{1 << 24, -1, "x"} {
		_, err := ty.Encode(v)
		wantInvalid(t, "30.1010", err)
	}
	if s := ty.Format(uint64(5)); s != "0b000000000000000000000101" {
		t.Errorf("Format = %q", s)
	}
	if v, err := ty.Parse("0x800001"); err != nil || v != uint64(0x800001) {
		t.Errorf("Parse = %v, %v", v, err)
	}
	if _, err := ty.Parse("0x1000000"); err == nil {
		t.Error("Parse of 25 bits succeeded")
	}
}
