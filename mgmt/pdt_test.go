// SPDX-License-Identifier: MIT

package mgmt_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/mgmt"
)

func TestPDT(t *testing.T) {
	for _, c := range []struct {
		p    mgmt.PDT
		v    uint8
		name string
		size int // 0: not fixed
	}{
		{mgmt.PDTControl, 0x00, "PDT_CONTROL", 0},
		{mgmt.PDTChar, 0x01, "PDT_CHAR", 1},
		{mgmt.PDTUnsignedChar, 0x02, "PDT_UNSIGNED_CHAR", 1},
		{mgmt.PDTInt, 0x03, "PDT_INT", 2},
		{mgmt.PDTUnsignedInt, 0x04, "PDT_UNSIGNED_INT", 2},
		{mgmt.PDTKNXFloat, 0x05, "PDT_KNX_FLOAT", 2},
		{mgmt.PDTDate, 0x06, "PDT_DATE", 3},
		{mgmt.PDTTime, 0x07, "PDT_TIME", 3},
		{mgmt.PDTLong, 0x08, "PDT_LONG", 4},
		{mgmt.PDTUnsignedLong, 0x09, "PDT_UNSIGNED_LONG", 4},
		{mgmt.PDTFloat, 0x0A, "PDT_FLOAT", 4},
		{mgmt.PDTDouble, 0x0B, "PDT_DOUBLE", 8},
		{mgmt.PDTCharBlock, 0x0C, "PDT_CHAR_BLOCK", 10},
		{mgmt.PDTPollGroupSetting, 0x0D, "PDT_POLL_GROUP_SETTING", 3},
		{mgmt.PDTShortCharBlock, 0x0E, "PDT_SHORT_CHAR_BLOCK", 5},
		{mgmt.PDTDateTime, 0x0F, "PDT_DATE_TIME", 8},
		{mgmt.PDTVariableLength, 0x10, "PDT_VARIABLE_LENGTH", 0},
		{mgmt.PDTGeneric01, 0x11, "PDT_GENERIC_01", 1},
		{mgmt.PDTGeneric06, 0x16, "PDT_GENERIC_06", 6},
		{mgmt.PDTGeneric10, 0x1A, "PDT_GENERIC_10", 10},
		{mgmt.PDTGeneric20, 0x24, "PDT_GENERIC_20", 20},
		{mgmt.PDTUTF8, 0x2F, "PDT_UTF8", 0},
		{mgmt.PDTVersion, 0x30, "PDT_VERSION", 2},
		{mgmt.PDTAlarmInfo, 0x31, "PDT_ALARM_INFO", 6},
		{mgmt.PDTBinaryInformation, 0x32, "PDT_BINARY_INFORMATION", 1},
		{mgmt.PDTBitset8, 0x33, "PDT_BITSET8", 1},
		{mgmt.PDTBitset16, 0x34, "PDT_BITSET16", 2},
		{mgmt.PDTEnum8, 0x35, "PDT_ENUM8", 1},
		{mgmt.PDTScaling, 0x36, "PDT_SCALING", 1},
		{mgmt.PDTNotEditableVariable, 0x3C, "PDT_NE_VL", 0},
		{mgmt.PDTNotEditableFixed, 0x3D, "PDT_NE_FL", 0},
		{mgmt.PDTFunction, 0x3E, "PDT_FUNCTION", 0},
		{mgmt.PDTEscape, 0x3F, "PDT_ESCAPE", 0},
		{mgmt.PDT(0x25), 0x25, "PDT(0x25)", 0},
		{mgmt.PDT(0x2E), 0x2E, "PDT(0x2E)", 0},
		{mgmt.PDT(0x37), 0x37, "PDT(0x37)", 0},
		{mgmt.PDT(0x40), 0x40, "PDT(0x40)", 0},
	} {
		if uint8(c.p) != c.v {
			t.Errorf("%s = 0x%02X, want 0x%02X", c.name, uint8(c.p), c.v)
		}
		if s := c.p.String(); s != c.name {
			t.Errorf("0x%02X: %q, want %q", c.v, s, c.name)
		}
		n, ok := c.p.Size()
		if ok != (c.size > 0) || (ok && n != c.size) {
			t.Errorf("%s: size %d %v, want %d", c.name, n, ok, c.size)
		}
	}
	// Every generic type is its number of octets.
	for p := mgmt.PDTGeneric01; p <= mgmt.PDTGeneric20; p++ {
		if n, ok := p.Size(); !ok || n != int(p-mgmt.PDTGeneric01)+1 {
			t.Errorf("%s: %d %v", p, n, ok)
		}
	}
}

func TestDescriptionCodec(t *testing.T) {
	for _, c := range []struct {
		d    mgmt.Description
		data []byte
	}{
		{mgmt.Description{Object: 2, PID: 76, Index: 9, Type: mgmt.PDTUnsignedChar, Writable: true, MaxElements: 30, Access: 0x31},
			[]byte{2, 76, 9, 0x82, 0x00, 0x1E, 0x31}},
		{mgmt.Description{Object: 0, PID: 11, Index: 3, Type: mgmt.PDTGeneric06, MaxElements: 0x0ABC, Access: 0xF0},
			[]byte{0, 11, 3, 0x16, 0x0A, 0xBC, 0xF0}},
		{mgmt.Description{PID: 50}, []byte{0, 50, 0, 0, 0, 0, 0}},
	} {
		if got := c.d.Data(); !bytes.Equal(got, c.data) {
			t.Errorf("%+v: % X, want % X", c.d, got, c.data)
		}
		tp, err := apdu.Parse(c.d.TPDU(data))
		if err != nil || tp.APCI != apdu.PropertyDescriptionResponseService {
			t.Fatalf("TPDU %+v %v", tp, err)
		}
		back, err := mgmt.ParseDescription(tp)
		if err != nil || back != c.d {
			t.Errorf("round trip %+v %v, want %+v", back, err, c.d)
		}
	}
	d := mgmt.Description{Access: 0x3C}
	if d.ReadLevel() != 3 || d.WriteLevel() != 12 {
		t.Errorf("levels %d %d", d.ReadLevel(), d.WriteLevel())
	}
	// Encoding: the type is masked to 6 bits, the maximum saturates.
	if b := (mgmt.Description{Type: 0xFF, MaxElements: 0xFFFF}).Data(); b[3] != 0x3F || b[4] != 0x0F || b[5] != 0xFF {
		t.Errorf("masking % X", b)
	}
	// Decoding ignores the reserved bits.
	r, err := mgmt.ParseDescription(apdu.TPDU{Data: []byte{1, 2, 3, 0xC5, 0xF0, 0x01, 0x00}})
	if err != nil || r.Type != mgmt.PDTKNXFloat || !r.Writable || r.MaxElements != 1 {
		t.Errorf("reserved bits: %+v %v", r, err)
	}
	// Short and long data.
	for _, b := range [][]byte{nil, {0, 1, 2, 3, 4, 5}, {0, 1, 2, 3, 4, 5, 6, 7}} {
		if _, err := mgmt.ParseDescription(apdu.TPDU{APCI: apdu.PropertyDescriptionResponseService, Data: b}); !errors.Is(err, knx.ErrMalformed) {
			t.Errorf("% X: %v", b, err)
		}
	}
	// The read request.
	tp, err := apdu.Parse(mgmt.DescriptionReadTPDU(data, 1, 0, 4))
	if err != nil || tp.APCI != apdu.PropertyDescriptionReadService || !bytes.Equal(tp.Data, []byte{1, 0, 4}) {
		t.Errorf("read %+v %v", tp, err)
	}
}

// The responder's answers decode to the Describer's descriptions, with
// the object of the request.
func TestResponderDescriptionRoundTrip(t *testing.T) {
	p := &props{name: []byte("abcd")}
	r := &mgmt.Responder{Address: dev, Properties: p}
	for _, c := range []struct{ pid, index uint8 }{{11, 0}, {76, 0}, {0, 0}, {0, 1}} {
		want, _ := p.DescribeProperty(0, c.pid, c.index)
		out := r.Handle(cemi.NewIndividualFrame(cemi.LDataInd, tool, dev, knx.PrioritySystem, mgmt.DescriptionReadTPDU(data, 0, c.pid, c.index)))
		got, err := mgmt.ParseDescription(parse(t, out[0]))
		if err != nil || got != want {
			t.Errorf("%d/%d: %+v %v, want %+v", c.pid, c.index, got, err, want)
		}
	}
	// No such object: a negative response for the requested object.
	out := r.Handle(frame(data, apdu.PropertyDescriptionReadService, 5, 11, 0))
	got, err := mgmt.ParseDescription(parse(t, out[0]))
	if err != nil || got != (mgmt.Description{Object: 5, PID: 11}) {
		t.Errorf("negative %+v %v", got, err)
	}
}
