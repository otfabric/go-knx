// SPDX-License-Identifier: MIT

package cemi

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/otfabric/go-knx"
)

func h(tb testing.TB, s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

// goldenCEMI are cEMI frames built by hand from the cEMI frame structure
// (message code, additional information, control fields, addresses, NPDU
// length, TPDU); addresses and values are arbitrary examples.
var goldenCEMI = []struct {
	name string
	hex  string
	want Frame
}{
	{"L_Data.req group write small", "11 00 bc e0 0000 0a03 01 0081",
		&LData{MsgCode: LDataReq, Ctrl1: 0xbc, Ctrl2: 0xe0, Destination: 0x0a03, TPDU: []byte{0x00, 0x81}}},
	{"L_Data.ind group response DPT 9", "29 00 bc e0 1105 0a03 03 0040 0c33",
		&LData{MsgCode: LDataInd, Ctrl1: 0xbc, Ctrl2: 0xe0, Source: 0x1105, Destination: 0x0a03, TPDU: []byte{0x00, 0x40, 0x0c, 0x33}}},
	{"L_Data.con with error", "2e 00 bd e0 1101 0a03 01 0081",
		&LData{MsgCode: LDataCon, Ctrl1: 0xbd, Ctrl2: 0xe0, Source: 0x1101, Destination: 0x0a03, TPDU: []byte{0x00, 0x81}}},
	{"L_Data.req individual T_Connect", "11 00 b0 60 0000 1105 00 80",
		&LData{MsgCode: LDataReq, Ctrl1: 0xb0, Ctrl2: 0x60, Destination: 0x1105, TPDU: []byte{0x80}}},
	{"L_Data.ind with additional info", "29 07 03 01 00 04 02 1234 bc e0 1105 0a03 01 0080",
		&LData{MsgCode: LDataInd, AddInfo: []AdditionalInfo{{Type: AddInfoBusmonitorStatus, Data: []byte{0}}, {Type: AddInfoTimestamp, Data: []byte{0x12, 0x34}}},
			Ctrl1: 0xbc, Ctrl2: 0xe0, Source: 0x1105, Destination: 0x0a03, TPDU: []byte{0x00, 0x80}}},
	{"L_Data.ind empty additional info block", "29 02 fe 00 bc e0 1105 0a03 01 0080",
		&LData{MsgCode: LDataInd, AddInfo: []AdditionalInfo{{Type: AddInfoManufacturer}}, Ctrl1: 0xbc, Ctrl2: 0xe0, Source: 0x1105, Destination: 0x0a03, TPDU: []byte{0x00, 0x80}}},
	{"L_Data.ind extended frame 16-octet NPDU", "29 00 3c e0 1105 0a03 10 0080 " + strings.Repeat("aa", 15),
		&LData{MsgCode: LDataInd, Ctrl1: 0x3c, Ctrl2: 0xe0, Source: 0x1105, Destination: 0x0a03, TPDU: append([]byte{0x00, 0x80}, bytes.Repeat([]byte{0xaa}, 15)...)}},
	{"L_Data.req standard 15-octet NPDU", "11 00 bc e0 0000 0a03 0f 0080 " + strings.Repeat("bb", 14),
		&LData{MsgCode: LDataReq, Ctrl1: 0xbc, Ctrl2: 0xe0, Destination: 0x0a03, TPDU: append([]byte{0x00, 0x80}, bytes.Repeat([]byte{0xbb}, 14)...)}},
	{"L_Busmon.ind", "2b 07 03 01 00 04 02 0001 bc 1105 0a03 e1 0081 ff",
		&Raw{MsgCode: LBusmonInd, AddInfo: []AdditionalInfo{{Type: 3, Data: []byte{0}}, {Type: 4, Data: []byte{0, 1}}}, Data: h(nil, "bc11050a03e10081ff")}},
	{"L_Raw.req", "10 00 bc 1105", &Raw{MsgCode: LRawReq, Data: []byte{0xbc, 0x11, 0x05}}},
	{"L_Raw.ind empty", "2d 00", &Raw{MsgCode: LRawInd}},
	{"L_Raw.con", "2f 00 01", &Raw{MsgCode: LRawCon, Data: []byte{1}}},
	{"M_PropRead.req", "fc 000b 01 35 1001",
		&Property{MsgCode: MPropReadReq, ObjectType: 11, Instance: 1, PropertyID: 53, Count: 1, Start: 1}},
	{"M_PropRead.con", "fb 000b 01 35 1001 00fa",
		&Property{MsgCode: MPropReadCon, ObjectType: 11, Instance: 1, PropertyID: 53, Count: 1, Start: 1, Data: []byte{0x00, 0xfa}}},
	{"M_PropRead.con negative", "fb 0000 01 01 0001 07",
		&Property{MsgCode: MPropReadCon, Instance: 1, PropertyID: 1, Start: 1, Data: []byte{7}}},
	{"M_PropWrite.req max count and start", "f6 0008 02 34 ffff 0102",
		&Property{MsgCode: MPropWriteReq, ObjectType: 8, Instance: 2, PropertyID: 0x34, Count: 15, Start: 0x0fff, Data: []byte{1, 2}}},
	{"M_PropWrite.con", "f5 0008 02 34 1001", &Property{MsgCode: MPropWriteCon, ObjectType: 8, Instance: 2, PropertyID: 0x34, Count: 1, Start: 1}},
	{"M_PropInfo.ind", "f7 0000 01 0e 1001 0a", &Property{MsgCode: MPropInfoInd, Instance: 1, PropertyID: 14, Count: 1, Start: 1, Data: []byte{10}}},
	{"M_FuncPropCommand.req", "f8 0003 01 3a 0001", &FunctionProperty{MsgCode: MFuncPropCommandReq, ObjectType: 3, Instance: 1, PropertyID: 0x3a, Data: []byte{0, 1}}},
	{"M_FuncPropStateRead.req", "f9 0003 01 3a", &FunctionProperty{MsgCode: MFuncPropStateReadReq, ObjectType: 3, Instance: 1, PropertyID: 0x3a}},
	{"M_FuncProp.con", "fa 0003 01 3a 00 01", &FunctionProperty{MsgCode: MFuncPropCon, ObjectType: 3, Instance: 1, PropertyID: 0x3a, Data: []byte{0, 1}}},
	{"M_Reset.req", "f1", &Reset{MsgCode: MResetReq}},
	{"M_Reset.ind", "f0", &Reset{MsgCode: MResetInd}},
	{"L_Poll_Data.req kept unknown", "13 00 b0 1105 0a03 05", &Unknown{MsgCode: LPollDataReq, Data: h(nil, "00b011050a0305")}},
	{"L_Poll_Data.con kept unknown", "25 00", &Unknown{MsgCode: LPollDataCon, Data: []byte{0}}},
	{"unknown code", "42 0102", &Unknown{MsgCode: 0x42, Data: []byte{1, 2}}},
	{"unknown code alone", "42", &Unknown{MsgCode: 0x42}},
}

func TestGolden(t *testing.T) {
	for _, g := range goldenCEMI {
		t.Run(g.name, func(t *testing.T) {
			b := h(t, g.hex)
			f, err := Parse(b)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !reflect.DeepEqual(f, g.want) {
				t.Fatalf("Parse:\n got %#v\nwant %#v", f, g.want)
			}
			if f.Code() != MessageCode(b[0]) {
				t.Fatalf("Code() = %v", f.Code())
			}
			out, err := Marshal(f)
			if err != nil || !bytes.Equal(out, b) {
				t.Fatalf("Marshal = % X, %v; want % X", out, err, b)
			}
		})
	}
}

func TestParseMalformed(t *testing.T) {
	cases := []struct{ name, hex string }{
		{"empty", ""},
		{"L_Data.req code only", "11"},
		{"additional info overrun", "29 05 03 01 00"},
		{"additional info block overrun", "29 03 04 02 00 bc e0 1105 0a03 01 0080"},
		{"additional info block one octet", "29 01 04 bc e0 1105 0a03 01 0080"},
		{"L_Data short header", "29 00 bc e0 1105 0a03"},
		{"L_Data NPDU length too long", "29 00 bc e0 1105 0a03 02 0080"},
		{"L_Data NPDU length too short", "29 00 bc e0 1105 0a03 00 0080"},
		{"L_Data missing TPCI", "29 00 bc e0 1105 0a03 00"},
		{"L_Data standard frame NPDU 16", "29 00 bc e0 1105 0a03 10 0080 " + strings.Repeat("aa", 15)},
		{"L_Busmon code only", "2b"},
		{"L_Raw additional info overrun", "10 02 01"},
		{"M_PropRead short", "fc 000b 01 35 10"},
		{"M_PropRead.req with data", "fc 000b 01 35 1001 00"},
		{"M_FuncProp short", "f8 0003 01"},
		{"M_Reset with data", "f1 00"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := Parse(h(t, c.hex))
			if !errors.Is(err, knx.ErrMalformed) || f != nil {
				t.Fatalf("Parse = %#v, %v; want ErrMalformed", f, err)
			}
		})
	}
}

func TestLDataAccessors(t *testing.T) {
	f := &LData{Ctrl1: 0xbc, Ctrl2: 0xe0, Destination: 0x0a03}
	if !f.Standard() || f.Repeat() || f.SystemBroadcast() || f.Priority() != knx.PriorityLow ||
		f.AckRequested() || f.ConfirmError() || !f.IsGroup() || f.HopCount() != 6 || f.ExtendedFormat() != 0 {
		t.Fatalf("defaults misread: %+v", f)
	}
	g, ok := f.Group()
	if !ok || g.String() != "1/2/3" {
		t.Fatalf("Group = %v %v", g, ok)
	}
	if _, ok := f.Individual(); ok {
		t.Fatal("Individual ok for a group destination")
	}
	if f.DestinationString() != "1/2/3" {
		t.Fatalf("DestinationString = %q", f.DestinationString())
	}

	f = &LData{Ctrl1: 0x03, Ctrl2: 0x05, Destination: 0x1105}
	if f.Standard() || !f.Repeat() || !f.SystemBroadcast() || f.Priority() != knx.PrioritySystem ||
		!f.AckRequested() || !f.ConfirmError() || f.IsGroup() || f.HopCount() != 0 || f.ExtendedFormat() != 5 {
		t.Fatalf("bits misread: %+v", f)
	}
	ia, ok := f.Individual()
	if !ok || ia.String() != "1.1.5" || f.DestinationString() != "1.1.5" {
		t.Fatalf("Individual = %v %v", ia, ok)
	}
	if _, ok := f.Group(); ok {
		t.Fatal("Group ok for an individual destination")
	}

	for _, p := range []knx.Priority{knx.PrioritySystem, knx.PriorityNormal, knx.PriorityUrgent, knx.PriorityLow} {
		f.SetPriority(p)
		if f.Priority() != p || f.Ctrl1&0xF3 != 0x03 {
			t.Fatalf("SetPriority(%v): ctrl1 %02X", p, f.Ctrl1)
		}
	}
	for n := uint8(0); n < 8; n++ {
		f.SetHopCount(n)
		if f.HopCount() != n || f.Ctrl2&0x8F != 0x05 {
			t.Fatalf("SetHopCount(%d): ctrl2 %02X", n, f.Ctrl2)
		}
	}
	f.SetHopCount(9) // masked to 3 bits
	if f.HopCount() != 1 {
		t.Fatalf("SetHopCount(9) = %d", f.HopCount())
	}
}

func TestNewFrames(t *testing.T) {
	src := knx.MustParseIndividualAddress("1.1.5")
	f := NewGroupFrame(LDataReq, src, knx.MustParseGroupAddress("1/2/3"), knx.PriorityNormal, []byte{0x00, 0x81})
	b, err := Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if want := h(t, "11 00 b4 e0 1105 0a03 01 0081"); !bytes.Equal(b, want) {
		t.Fatalf("group frame % X, want % X", b, want)
	}
	if f.String() != "L_Data.req 1.1.5 -> 1/2/3 normal hop 6 tpdu 0081" {
		t.Fatalf("String = %q", f.String())
	}

	// A TPDU with an NPDU over 15 octets switches to an extended frame.
	long := make([]byte, 17)
	f = NewGroupFrame(LDataReq, src, 1, knx.PriorityLow, long)
	if f.Standard() {
		t.Fatal("long TPDU kept as standard frame")
	}
	if b, err := Marshal(f); err != nil || b[2] != 0x3c || b[8] != 16 {
		t.Fatalf("extended frame % X, %v", b, err)
	}
	f = NewGroupFrame(LDataReq, src, 1, knx.PriorityLow, make([]byte, 16))
	if !f.Standard() {
		t.Fatal("15-octet NPDU made extended")
	}

	f = NewIndividualFrame(LDataReq, 0, src, knx.PrioritySystem, []byte{0x80})
	if f.IsGroup() || f.HopCount() != 6 || f.Priority() != knx.PrioritySystem {
		t.Fatalf("individual frame %+v", f)
	}
	if b, _ := Marshal(f); !bytes.Equal(b, h(t, "11 00 b0 60 0000 1105 00 80")) {
		t.Fatalf("individual frame % X", b)
	}
}

func TestLDataEncodeErrors(t *testing.T) {
	cases := []struct {
		name string
		f    *LData
	}{
		{"empty TPDU", &LData{Ctrl1: Ctrl1Standard}},
		{"TPDU over 256", &LData{TPDU: make([]byte, 257)}},
		{"standard frame NPDU 16", &LData{Ctrl1: Ctrl1Standard, TPDU: make([]byte, 17)}},
		{"additional info block over 255", &LData{TPDU: []byte{0, 0}, AddInfo: []AdditionalInfo{{Type: 1, Data: make([]byte, 256)}}}},
		{"additional info total over 255", &LData{TPDU: []byte{0, 0}, AddInfo: []AdditionalInfo{{Type: 1, Data: make([]byte, 200)}, {Type: 2, Data: make([]byte, 60)}}}},
	}
	for _, c := range cases {
		if b, err := Marshal(c.f); !errors.Is(err, knx.ErrInvalidValue) || b != nil {
			t.Errorf("%s: % X, %v", c.name, b, err)
		}
	}
	// The largest frames are accepted.
	f := &LData{MsgCode: LDataInd, TPDU: make([]byte, 256), AddInfo: []AdditionalInfo{{Type: 1, Data: make([]byte, 253)}}}
	b, err := Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(b)
	if err != nil || !reflect.DeepEqual(back.(*LData).TPDU, f.TPDU) || len(back.(*LData).AddInfo[0].Data) != 253 {
		t.Fatalf("max frame round trip: %v", err)
	}
	if _, err := Marshal(&Raw{MsgCode: LRawReq, AddInfo: []AdditionalInfo{{Data: make([]byte, 300)}}}); !errors.Is(err, knx.ErrInvalidValue) {
		t.Errorf("Raw with oversized additional info: %v", err)
	}
}

func TestPropertyEncodeErrors(t *testing.T) {
	for _, p := range []*Property{{MsgCode: MPropReadReq, Count: 16}, {MsgCode: MPropReadReq, Start: 0x1000}} {
		if _, err := Marshal(p); !errors.Is(err, knx.ErrInvalidValue) {
			t.Errorf("%+v: %v", p, err)
		}
	}
}

func TestClone(t *testing.T) {
	f := &LData{MsgCode: LDataInd, AddInfo: []AdditionalInfo{{Type: 4, Data: []byte{1, 2}}}, TPDU: []byte{0, 0x81}}
	c := f.Clone()
	if !reflect.DeepEqual(c, f) {
		t.Fatal("clone differs")
	}
	c.TPDU[1] = 0x80
	c.AddInfo[0].Data[0] = 9
	if f.TPDU[1] != 0x81 || f.AddInfo[0].Data[0] != 1 {
		t.Fatal("clone shares memory")
	}
	if (&LData{}).Clone().AddInfo != nil {
		t.Fatal("clone of no additional info is not nil")
	}
}

func TestParseCopies(t *testing.T) {
	b := h(t, "29 02 04 00 bc e0 1105 0a03 01 0081")
	f, _ := Parse(b)
	for i := range b {
		b[i] = 0xff
	}
	if got, _ := Marshal(f); !bytes.Equal(got, h(t, "29 02 04 00 bc e0 1105 0a03 01 0081")) {
		t.Fatalf("decoded frame aliases input: % X", got)
	}
}

func TestMessageCodeString(t *testing.T) {
	for c, want := range map[MessageCode]string{LDataReq: "L_Data.req", LDataInd: "L_Data.ind", LDataCon: "L_Data.con",
		MPropReadReq: "M_PropRead.req", MResetInd: "M_Reset.ind", LBusmonInd: "L_Busmon.ind", 0x42: "0x42"} {
		if c.String() != want {
			t.Errorf("%02X: %q", uint8(c), c.String())
		}
	}
}

func TestDefaults(t *testing.T) {
	if DefaultCtrl1 != 0xbc || DefaultCtrl2 != 0xe0 {
		t.Fatalf("defaults %02X %02X", DefaultCtrl1, DefaultCtrl2)
	}
}
