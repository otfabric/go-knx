// SPDX-License-Identifier: MIT

package knxnetip

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/otfabric/go-knx"
)

// abbSearchResponseExt is the SEARCH_RESPONSE_EXTENDED of an ABB IP-Router
// IPR/S recorded in testdata/captures/wireshark-14825
// (test-tool_abb-ipr-s_01-core.txt, frame 1048). Its TUNNELLING_INFO block
// (22 octets: no maximum APDU length, five slots) and its
// SECURED_SERVICE_FAMILIES block (11 octets) do not have the layout of
// their types; Wireshark marks both malformed too.
const abbSearchResponseExt = "0610020c007b0801c0a8000a0e573601020021000000000281fdff50e000170c000cde02808e" +
	"4142422049502d526f75746572204950522f5300000000000000000000000e02020103020402050107010901080800000038091a" +
	"160721010000210200002103000021040000210500000b06000000000000000001"

// TestRecordedMalformedOptionalDIB: the router's response used to be
// refused whole, so discovery did not see the router at all.
func TestRecordedMalformedOptionalDIB(t *testing.T) {
	b, _ := hex.DecodeString(abbSearchResponseExt)
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	r := m.(*SearchResponse)
	di, ok := r.DIBs.DeviceInfo()
	if !ok || di.Name != "ABB IP-Router IPR/S" || di.Address != knx.MustParseIndividualAddress("2.1.0") {
		t.Fatalf("device info %+v %v", di, ok)
	}
	if fam, ok := r.DIBs.SupportedServices(); !ok || len(fam.Families) != 6 {
		t.Fatalf("supported services %+v %v", fam, ok)
	}
	if d, ok := r.DIBs.Find(DIBTunnellingInfo); !ok {
		t.Fatal("no tunnelling info block")
	} else if u, ok := d.(UnknownDIB); !ok || len(u.Data) != 20 {
		t.Fatalf("tunnelling info %#v", d)
	}
	if _, ok := r.DIBs.SecuredServices(); ok {
		t.Fatal("the malformed secured service families block decoded")
	}
	if e, err := Marshal(m); err != nil || !bytes.Equal(e, b) {
		t.Fatalf("encoded % X, %v", e, err)
	}
	// Without a DEVICE_INFO block the malformed block is an error, and a
	// malformed DEVICE_INFO block always is.
	if _, err := ParseDIBs(b[82:]); !errors.Is(err, knx.ErrMalformed) {
		t.Fatalf("blocks without device info: %v", err)
	}
	bad := append([]byte{}, b[14:]...)
	bad[0] = 0x35 // DEVICE_INFO one octet short, framing intact
	if _, err := ParseDIBs(bad); !errors.Is(err, knx.ErrMalformed) {
		t.Fatalf("malformed device info: %v", err)
	}
}
