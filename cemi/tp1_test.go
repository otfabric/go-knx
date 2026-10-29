// SPDX-License-Identifier: MIT

package cemi

import (
	"bytes"
	"errors"
	"testing"

	"github.com/otfabric/go-knx"
)

func TestTP1RoundTrip(t *testing.T) {
	for _, f := range []*LData{
		NewGroupFrame(LDataReq, knx.MustParseIndividualAddress("1.1.10"), knx.MustParseGroupAddress("1/2/3"), knx.PriorityLow, []byte{0x00, 0x81}),
		NewGroupFrame(LDataInd, knx.MustParseIndividualAddress("15.15.255"), knx.MustParseGroupAddress("31/7/255"), knx.PriorityUrgent, []byte{0x00, 0x80, 0x0C, 0x33}),
		NewIndividualFrame(LDataReq, knx.MustParseIndividualAddress("1.1.1"), knx.MustParseIndividualAddress("1.1.2"), knx.PrioritySystem, []byte{0x80}),
	} {
		b, err := TP1Frame(f)
		if err != nil {
			t.Fatal(err)
		}
		g, err := ParseTP1(b)
		if err != nil {
			t.Fatalf("% X: %v", b, err)
		}
		if g.Source != f.Source || g.Destination != f.Destination || g.IsGroup() != f.IsGroup() || g.Priority() != f.Priority() ||
			g.HopCount() != f.HopCount() || !bytes.Equal(g.TPDU, f.TPDU) || g.MsgCode != LDataInd {
			t.Fatalf("% X: %s, want %s", b, g, f)
		}
	}
	// A frame for the TP1 reference: 1.1.10 -> 1/2/3 write on, low priority.
	b, _ := TP1Frame(NewGroupFrame(LDataReq, knx.MustParseIndividualAddress("1.1.10"), knx.MustParseGroupAddress("1/2/3"), knx.PriorityLow, []byte{0x00, 0x81}))
	if want := []byte{0xBC, 0x11, 0x0A, 0x0A, 0x03, 0xE1, 0x00, 0x81}; !bytes.Equal(b[:len(b)-1], want) {
		t.Fatalf("frame % X, want % X + check octet", b, want)
	}
}

func TestTP1Errors(t *testing.T) {
	long := NewGroupFrame(LDataReq, 1, 1, knx.PriorityLow, make([]byte, 17))
	if _, err := TP1Frame(long); !errors.Is(err, knx.ErrUnsupported) {
		t.Fatalf("extended: %v", err)
	}
	good, _ := TP1Frame(NewGroupFrame(LDataReq, 1, 1, knx.PriorityLow, []byte{0x00, 0x81}))
	for name, b := range map[string][]byte{
		"short":    good[:5],
		"length":   append(append([]byte{}, good[:len(good)-1]...), 0x00, good[len(good)-1]),
		"checksum": append(append([]byte{}, good[:len(good)-1]...), good[len(good)-1]^0xFF),
	} {
		if _, err := ParseTP1(b); !errors.Is(err, knx.ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	ext := append([]byte{}, good...)
	ext[0] &^= 0x80
	if _, err := ParseTP1(ext); !errors.Is(err, knx.ErrUnsupported) {
		t.Errorf("extended control field: %v", err)
	}
	rep := append([]byte{}, good...)
	rep[0] &^= 0x20
	var x byte
	for _, c := range rep[:len(rep)-1] {
		x ^= c
	}
	rep[len(rep)-1] = ^x
	if f, err := ParseTP1(rep); err != nil || f.Repeat() != true {
		t.Errorf("repeated frame: %v %v", f, err)
	}
}

func FuzzParseTP1(f *testing.F) {
	good, _ := TP1Frame(NewGroupFrame(LDataReq, 1, 1, knx.PriorityLow, []byte{0x00, 0x81}))
	f.Add(good)
	f.Add([]byte{0xBC})
	f.Fuzz(func(t *testing.T, b []byte) {
		ld, err := ParseTP1(b)
		if err != nil {
			return
		}
		// A frame that decodes encodes back to the same octets, except the
		// repeat bit, which TP1Frame always clears (an original frame).
		again, err := TP1Frame(ld)
		if err != nil {
			t.Fatalf("% X decodes but does not encode: %v", b, err)
		}
		if !bytes.Equal(again[1:len(again)-1], b[1:len(b)-1]) {
			t.Fatalf("% X -> % X", b, again)
		}
	})
}
