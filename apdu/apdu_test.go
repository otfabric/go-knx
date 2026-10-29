// SPDX-License-Identifier: MIT

package apdu

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/otfabric/go-knx"
)

func TestTPCI(t *testing.T) {
	cases := []struct {
		octet byte
		want  TPCI
	}{
		{0x00, TPCI{Kind: TData}},
		{0x03, TPCI{Kind: TData}}, // APCI bits are not part of the TPCI
		{0x04, TPCI{Kind: TDataTagGroup}},
		{0x40, TPCI{Kind: TDataConnected}},
		{0x40 | 5<<2 | 0x03, TPCI{Kind: TDataConnected, Seq: 5}},
		{0x7C, TPCI{Kind: TDataConnected, Seq: 15}},
		{0x80, TPCI{Kind: TConnect}},
		{0x81, TPCI{Kind: TDisconnect}},
		{0xC2, TPCI{Kind: TAck}},
		{0xC2 | 9<<2, TPCI{Kind: TAck, Seq: 9}},
		{0xC3 | 15<<2, TPCI{Kind: TNak, Seq: 15}},
	}
	for _, c := range cases {
		got, err := ParseTPCI(c.octet)
		if err != nil || got != c.want {
			t.Errorf("ParseTPCI(%02X) = %+v, %v; want %+v", c.octet, got, err, c.want)
		}
		if got.Octet() != c.octet&^tpciAPCIBits(got) {
			t.Errorf("%+v.Octet() = %02X, want %02X", got, got.Octet(), c.octet&^tpciAPCIBits(got))
		}
	}
	for _, b := range []byte{0x08, 0x3C, 0x82, 0xBF, 0xC0, 0xC1, 0xFC} {
		if _, err := ParseTPCI(b); !errors.Is(err, knx.ErrMalformed) {
			t.Errorf("ParseTPCI(%02X): %v, want ErrMalformed", b, err)
		}
	}
	// Seq is masked to 4 bits on encode.
	if o := (TPCI{Kind: TAck, Seq: 0x1F}).Octet(); o != 0xC2|15<<2 {
		t.Errorf("Octet with seq 31 = %02X", o)
	}
	if (TPCI{Kind: TKind(99)}).Octet() != 0 {
		t.Error("unknown kind does not encode as T_Data")
	}
	for k, want := range map[TKind]bool{TData: false, TDataTagGroup: false, TDataConnected: false, TConnect: true, TDisconnect: true, TAck: true, TNak: true} {
		if (TPCI{Kind: k}).IsControl() != want {
			t.Errorf("%s.IsControl() != %v", k, want)
		}
	}
}

// tpciAPCIBits are the low bits of the octet that belong to the APCI.
func tpciAPCIBits(t TPCI) byte {
	if t.IsControl() {
		return 0
	}
	return 0x03
}

func TestParse(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want TPDU
	}{
		{"group read", []byte{0x00, 0x00}, TPDU{APCI: GroupValueReadService}},
		{"group write small", []byte{0x00, 0x81}, TPDU{APCI: GroupValueWriteService, Short: 1}},
		{"group write small max", []byte{0x00, 0xBF}, TPDU{APCI: GroupValueWriteService, Short: 63}},
		{"group response long", []byte{0x00, 0x40, 0x0c, 0x33}, TPDU{APCI: GroupValueResponseService, Data: []byte{0x0c, 0x33}}},
		{"memory read 4-bit with count", []byte{0x42, 0x03, 0x01, 0x00}, TPDU{TPCI: TPCI{Kind: TDataConnected}, APCI: MemoryReadService, Short: 3, Data: []byte{0x01, 0x00}}},
		{"device descriptor read", []byte{0x43, 0x00}, TPDU{TPCI: TPCI{Kind: TDataConnected}, APCI: DeviceDescriptorReadService}},
		{"individual address read 10-bit", []byte{0x01, 0x00}, TPDU{APCI: IndividualAddressReadService}},
		{"property value read 10-bit", []byte{0x43 | 2<<2, 0xD5, 0x00, 0x0b, 0x10, 0x01}, TPDU{TPCI: TPCI{Kind: TDataConnected, Seq: 2}, APCI: PropertyValueReadService, Data: []byte{0x00, 0x0b, 0x10, 0x01}}},
		{"ADC response small", []byte{0x01, 0xC5, 0xAA}, TPDU{APCI: ADCResponseService, Short: 5, Data: []byte{0xAA}}},
		{"system network parameter read shares ADC_Response bits", []byte{0x01, 0xC8}, TPDU{APCI: SystemNetworkParameterReadService}},
		{"memory extended read", []byte{0x01, 0xFD}, TPDU{APCI: MemoryExtendedReadService}},
		{"restart 10-bit", []byte{0x03, 0x80}, TPDU{APCI: RestartService}},
		{"tag group", []byte{0x04, 0x80, 0x01}, TPDU{TPCI: TPCI{Kind: TDataTagGroup}, APCI: GroupValueWriteService, Data: []byte{1}}},
		{"T_Connect", []byte{0x80}, TPDU{TPCI: TPCI{Kind: TConnect}}},
		{"T_ACK seq 3", []byte{0xCE}, TPDU{TPCI: TPCI{Kind: TAck, Seq: 3}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Parse(c.in)
			if err != nil || !reflect.DeepEqual(got, c.want) {
				t.Fatalf("Parse(% X) = %+v, %v; want %+v", c.in, got, err, c.want)
			}
			if b := got.Bytes(); !bytes.Equal(b, c.in) {
				t.Fatalf("Bytes() = % X, want % X", b, c.in)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	for _, b := range [][]byte{nil, {0x00}, {0x40}, {0x80, 0x00}, {0xC2, 0x00}, {0x08, 0x00}} {
		if _, err := Parse(b); !errors.Is(err, knx.ErrMalformed) {
			t.Errorf("Parse(% X): %v, want ErrMalformed", b, err)
		}
	}
}

func TestParseCopiesData(t *testing.T) {
	in := []byte{0x00, 0x80, 0x01, 0x02}
	p, _ := Parse(in)
	in[2] = 0xFF
	if p.Data[0] != 0x01 {
		t.Fatal("Data aliases the input")
	}
}

func TestAppend(t *testing.T) {
	// The 6-bit parameter is masked; the APCI is masked to 10 bits.
	if b := (TPDU{APCI: GroupValueWriteService, Short: 0xFF}).Bytes(); !bytes.Equal(b, []byte{0x00, 0xBF}) {
		t.Errorf("short masked: % X", b)
	}
	if b := (TPDU{APCI: 0xFFFF&0x3D5 | 0xFC00}).Bytes(); !bytes.Equal(b, []byte{0x03, 0xD5}) {
		t.Errorf("APCI masked: % X", b)
	}
	// Short is ignored for a 10-bit APCI.
	if b := (TPDU{APCI: PropertyValueReadService, Short: 7}).Bytes(); !bytes.Equal(b, []byte{0x03, 0xD5}) {
		t.Errorf("short with 10-bit APCI: % X", b)
	}
	// Control PDUs carry no APCI or data.
	if b := (TPDU{TPCI: TPCI{Kind: TDisconnect}, APCI: GroupValueWriteService, Data: []byte{1}}).Bytes(); !bytes.Equal(b, []byte{0x81}) {
		t.Errorf("T_Disconnect: % X", b)
	}
	if b := (TPDU{APCI: GroupValueReadService}).Append([]byte{0xEE}); !bytes.Equal(b, []byte{0xEE, 0x00, 0x00}) {
		t.Errorf("Append: % X", b)
	}
}

func TestHas6BitData(t *testing.T) {
	cases := map[APCI]bool{
		GroupValueReadService: true, GroupValueResponseService | 0x3F: true, GroupValueWriteService | 1: true,
		ADCReadService: true, ADCResponseService: true, ADCResponseService | 7: true, MemoryReadService: true,
		MemoryResponseService: true, MemoryWriteService: true, DeviceDescriptorReadService: true, DeviceDescriptorResponseService: true,
		SystemNetworkParameterReadService: false, MemoryExtendedReadService: false, IndividualAddressWriteService: false,
		IndividualAddressReadService: false, IndividualAddressResponseService: false, UserMemoryReadService: false,
		RestartService: false, PropertyValueReadService: false, SecureService: false,
	}
	for a, want := range cases {
		if a.Has6BitData() != want {
			t.Errorf("%s (%03X).Has6BitData() = %v", a, uint16(a), !want)
		}
	}
}

func TestStrings(t *testing.T) {
	cases := []struct{ got, want string }{
		{GroupValueWriteService.String(), "A_GroupValue_Write"},
		{PropertyValueResponseService.String(), "A_PropertyValue_Response"},
		{SecureService.String(), "SecureService"},
		{APCI(0x3FF).String(), "APCI(0x3FF)"},
		{TData.String(), "T_Data"}, {TDataTagGroup.String(), "T_Data_Tag_Group"},
		{TDataConnected.String(), "T_Data_Connected"}, {TConnect.String(), "T_Connect"},
		{TDisconnect.String(), "T_Disconnect"}, {TAck.String(), "T_ACK"}, {TNak.String(), "T_NAK"},
		{TKind(42).String(), "TKind(42)"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
	// Every named service encodes and decodes to itself (a 4-bit service
	// with parameter 0).
	for a := range apciNames {
		p, err := Parse(TPDU{APCI: a}.Bytes())
		if err != nil || p.APCI != a {
			t.Errorf("%s: decoded %s, %v", a, p.APCI, err)
		}
	}
}

func TestGroupValueBuilders(t *testing.T) {
	if !bytes.Equal(GroupValueRead(), []byte{0, 0}) {
		t.Fatal("GroupValueRead")
	}
	cases := []struct {
		name string
		fn   func(GroupValue) ([]byte, error)
		v    GroupValue
		want []byte
	}{
		{"write small 0", GroupValueWrite, GroupValue{Data: []byte{0}, Small: true}, []byte{0x00, 0x80}},
		{"write small 63", GroupValueWrite, GroupValue{Data: []byte{63}, Small: true}, []byte{0x00, 0xBF}},
		{"response small 1", GroupValueResponse, GroupValue{Data: []byte{1}, Small: true}, []byte{0x00, 0x41}},
		{"write long one octet", GroupValueWrite, GroupValue{Data: []byte{0x01}}, []byte{0x00, 0x80, 0x01}},
		{"response long", GroupValueResponse, GroupValue{Data: []byte{0x0c, 0x33}}, []byte{0x00, 0x40, 0x0c, 0x33}},
		{"write 254 octets", GroupValueWrite, GroupValue{Data: make([]byte, 254)}, append([]byte{0x00, 0x80}, make([]byte, 254)...)},
	}
	for _, c := range cases {
		got, err := c.fn(c.v)
		if err != nil || !bytes.Equal(got, c.want) {
			t.Errorf("%s: % X, %v", c.name, got, err)
		}
	}
	for _, v := range []GroupValue{
		{Small: true}, {Data: []byte{64}, Small: true}, {Data: []byte{1, 2}, Small: true},
		{}, {Data: make([]byte, 255)},
	} {
		if b, err := GroupValueWrite(v); !errors.Is(err, knx.ErrInvalidValue) || b != nil {
			t.Errorf("GroupValueWrite(%+v) = % X, %v", v, b, err)
		}
	}
}

func TestParseGroupValue(t *testing.T) {
	cases := []struct {
		in   []byte
		svc  APCI
		want GroupValue
	}{
		{[]byte{0x00, 0x00}, GroupValueReadService, GroupValue{}},
		{[]byte{0x00, 0x81}, GroupValueWriteService, GroupValue{Data: []byte{1}, Small: true}},
		{[]byte{0x00, 0x40}, GroupValueResponseService, GroupValue{Data: []byte{0}, Small: true}},
		{[]byte{0x00, 0x80, 0x0c, 0x33}, GroupValueWriteService, GroupValue{Data: []byte{0x0c, 0x33}}},
	}
	for _, c := range cases {
		svc, v, err := ParseGroupValue(c.in)
		if err != nil || svc != c.svc || !reflect.DeepEqual(v, c.want) {
			t.Errorf("ParseGroupValue(% X) = %s %+v %v", c.in, svc, v, err)
		}
	}
	// A value re-encodes to the same TPDU.
	for _, c := range cases[1:4] {
		_, v, _ := ParseGroupValue(c.in)
		b, err := groupValue(c.svc, v)
		if err != nil || !bytes.Equal(b, c.in) {
			t.Errorf("re-encode % X: % X %v", c.in, b, err)
		}
	}

	errCases := []struct {
		in   []byte
		want error
	}{
		{nil, knx.ErrMalformed},
		{[]byte{0x00}, knx.ErrMalformed},
		{[]byte{0x00, 0x01}, knx.ErrMalformed},         // read with a small value
		{[]byte{0x00, 0x00, 0x01}, knx.ErrMalformed},   // read with data
		{[]byte{0x80}, knx.ErrUnsupported},             // T_Connect
		{[]byte{0x40, 0x80}, knx.ErrUnsupported},       // connected data
		{[]byte{0x04, 0x80}, knx.ErrUnsupported},       // tag group
		{[]byte{0x01, 0x00}, knx.ErrUnsupported},       // A_IndividualAddress_Read
		{[]byte{0x02, 0x00, 0x01}, knx.ErrUnsupported}, // A_Memory_Read
		{[]byte{0x03, 0x40, 0x0c}, knx.ErrUnsupported}, // A_DeviceDescriptor_Response
	}
	for _, c := range errCases {
		if _, _, err := ParseGroupValue(c.in); !errors.Is(err, c.want) {
			t.Errorf("ParseGroupValue(% X): %v, want %v", c.in, err, c.want)
		}
	}
}
