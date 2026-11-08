// SPDX-License-Identifier: MIT

package datasecure_test

import (
	"bytes"
	"testing"

	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/datasecure"
	"github.com/otfabric/go-knx/internal/capture"
	"github.com/otfabric/go-knx/knxnetip"
)

// TestCaptureDataSecure opens the S-A_Data of frame 138 of Wireshark's
// cEMI test capture (1.2.3 -> 1.1.1) with the destination's key from
// Wireshark's test keyring (B0 B1 .. BF, test/keys/knx_keyring.xml):
// sequence number 7 and the plain A_DeviceDescriptor_Read, as Wireshark
// decrypts it ("MAC OK"). Another key fails.
func TestCaptureDataSecure(t *testing.T) {
	f, err := capture.Load("wireshark/wireshark-test_synthetic_cemi-coverage.pcap.gz")
	if err != nil {
		t.Fatal(err)
	}
	var ld *cemi.LData
	for _, d := range f.IP {
		if d.Frame != 138 {
			continue
		}
		m, err := knxnetip.Parse(d.Data)
		if err != nil {
			t.Fatal(err)
		}
		c, err := cemi.Parse(m.(*knxnetip.RoutingIndication).CEMI)
		if err != nil {
			t.Fatal(err)
		}
		ld = c.(*cemi.LData)
	}
	if ld == nil || !datasecure.IsSecure(ld) {
		t.Fatalf("frame 138: %v", ld)
	}
	key := datasecure.Key{0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF}
	plain, seq, scf, err := datasecure.Open(key, ld)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 7 || scf.Service != datasecure.SData || scf.Algorithm != datasecure.AuthConf || !bytes.Equal(plain.TPDU, []byte{0x03, 0x00}) {
		t.Fatalf("seq %d scf %+v plain %s", seq, scf, plain)
	}
	key[0] ^= 1
	if _, _, _, err := datasecure.Open(key, ld); err == nil {
		t.Fatal("other key opened the frame")
	}
}
