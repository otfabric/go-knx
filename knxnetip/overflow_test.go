// SPDX-License-Identifier: MIT

package knxnetip

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"

	"github.com/otfabric/go-knx"
)

// unknownDIB returns the encoding of an unknown DIB of n octets in all.
func unknownDIB(t DIBType, n int) []byte {
	b := make([]byte, n)
	b[0], b[1] = byte(n), byte(t)
	return b
}

// A structure whose length does not fit its length octet used to be
// written with the length wrapped modulo 256. For an unknown DIB of 256
// data octets that is 2: the frame encoded and decoded, but as three DIBs
// smuggled out of the caller's data instead of the one it passed.
func TestAppendDIBLengthOverflow(t *testing.T) {
	inner := append(unknownDIB(0xF0, 128), unknownDIB(0xF0, 128)...)
	m := &SearchResponse{
		Control: HPAI{Protocol: IPv4UDP, Addr: netip.MustParseAddrPort("192.168.1.2:3671")},
		DIBs:    DIBs{UnknownDIB{DIBType: 0xF1, Data: inner}},
	}
	if b, err := Marshal(m); !errors.Is(err, knx.ErrInvalidValue) {
		t.Fatalf("Marshal = % X, %v; want ErrInvalidValue", b, err)
	}
	// The largest DIB that fits still encodes.
	m.DIBs = DIBs{UnknownDIB{DIBType: 0xF1, Data: make([]byte, 253)}}
	b, err := Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(b)
	if err != nil || len(got.(*SearchResponse).DIBs) != 1 {
		t.Fatalf("Parse = %+v, %v", got, err)
	}
}

// Every structure length octet that does not fit is written as 0, which
// the decoders reject, rather than wrapped.
func TestAppendToLengthOctetOverflow(t *testing.T) {
	addrs := make([]knx.IndividualAddress, 127) // 2+254 = 256
	slots := make([]TunnelSlot, 63)             // 4+252 = 256
	fams := make([]ServiceFamily, 127)          // 2+254 = 256
	for _, c := range []struct {
		name string
		b    []byte
	}{
		{"service families", ServiceFamilies{Families: fams}.AppendTo(nil)},
		{"KNX addresses", KNXAddresses{Addresses: addrs}.AppendTo(nil)},
		{"tunnelling info", TunnellingInfo{Slots: slots}.AppendTo(nil)},
		{"manufacturer data", ManufacturerData{Data: make([]byte, 252)}.AppendTo(nil)},
		{"unknown DIB", UnknownDIB{DIBType: 0xF1, Data: make([]byte, 254)}.AppendTo(nil)},
		{"CRI", CRI{Type: DeviceManagementConnection + 0x10, Data: make([]byte, 256)}.AppendTo(nil)},
		{"CRD", CRD{Type: DeviceManagementConnection + 0x10, Data: make([]byte, 256)}.AppendTo(nil)},
	} {
		if c.b[0] != 0 {
			t.Errorf("%s: length octet %d, want 0", c.name, c.b[0])
		}
	}
	m := &SearchRequestExt{Discovery: HPAI{Protocol: IPv4UDP, Addr: netip.MustParseAddrPort("192.168.1.2:3671")},
		Params: []SearchParam{{Type: 0x7E, Data: append(unknownDIB(0x01, 128), unknownDIB(0x01, 128)...)}}}
	if b, err := Marshal(m); !errors.Is(err, knx.ErrInvalidValue) {
		t.Fatalf("search parameter: Marshal = % X, %v; want ErrInvalidValue", b, err)
	}
}

// A total length past 16 bits used to wrap (65536+6 framed as 6).
func TestAppendHeaderLengthOverflow(t *testing.T) {
	for _, n := range []int{0xFFFF - HeaderLen + 1, 0x10000, -1} {
		b := AppendHeader(nil, SearchRequestType, n)
		if !bytes.Equal(b[4:], []byte{0, 0}) {
			t.Errorf("bodyLen %d: total length % X, want 00 00", n, b[4:])
		}
		if _, err := ParseHeader(b); !errors.Is(err, knx.ErrMalformed) {
			t.Errorf("bodyLen %d: ParseHeader = %v", n, err)
		}
	}
	if b := AppendHeader(nil, SearchRequestType, 0xFFFF-HeaderLen); !bytes.Equal(b[4:], []byte{0xFF, 0xFF}) {
		t.Errorf("largest length % X", b[4:])
	}
}
