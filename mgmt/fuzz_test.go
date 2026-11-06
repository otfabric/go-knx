// SPDX-License-Identifier: MIT

package mgmt_test

import (
	"bytes"
	"testing"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/datasecure"
	"github.com/otfabric/go-knx/mgmt"
)

// FuzzResponder feeds a sequence of arbitrary TPDUs (each prefixed with
// its length, the first octet of the input selects the message code and
// the sender) to a plain and to a secured Responder, which keep their
// transport layer state across the sequence. Nothing may panic; every
// answer must come from the device, go to the sender, encode as cEMI and,
// from the plain responder, decode as a TPDU; no frame is answered with
// more than two frames (an ACK and a response).
func FuzzResponder(f *testing.F) {
	seq := func(tpdus ...[]byte) []byte {
		b := []byte{0}
		for _, t := range tpdus {
			b = append(append(b, byte(len(t))), t...)
		}
		return b
	}
	data := apdu.TPCI{Kind: apdu.TData}
	conn := apdu.TPCI{Kind: apdu.TDataConnected}
	p := mgmt.Property{Object: 0, PID: 76, Start: 1, Count: 2}
	f.Add(seq(apdu.TPDU{TPCI: data, APCI: apdu.DeviceDescriptorReadService}.Bytes()))
	f.Add(seq(p.TPDU(data, apdu.PropertyValueReadService)))
	f.Add(seq(apdu.TPDU{TPCI: apdu.TPCI{Kind: apdu.TConnect}}.Bytes(),
		p.TPDU(conn, apdu.PropertyValueReadService),
		apdu.TPDU{TPCI: apdu.TPCI{Kind: apdu.TAck}}.Bytes(),
		apdu.TPDU{TPCI: apdu.TPCI{Kind: apdu.TDisconnect}}.Bytes()))
	f.Add(seq(apdu.TPDU{TPCI: data, APCI: apdu.PropertyValueWriteService, Data: []byte{0, 76, 0x20, 0x01, 'x', 'y'}}.Bytes()))
	f.Add(seq(apdu.TPDU{TPCI: data, APCI: apdu.PropertyDescriptionReadService, Data: []byte{0, 0, 1}}.Bytes()))
	toolTab, _ := datasecure.NewTable(nil, nil, 10)
	toolTab.SetToolKey(dev, datasecure.Key{1, 2, 3})
	if req, _, err := toolTab.SyncRequest(cemi.LDataInd, tool, dev, 0); err == nil {
		f.Add(seq(req.TPDU))
	}
	if s, err := toolTab.SealToolRequest(cemi.NewIndividualFrame(cemi.LDataInd, tool, dev, knx.PrioritySystem, p.TPDU(data, apdu.PropertyValueReadService))); err == nil {
		f.Add(seq(s.TPDU))
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) == 0 {
			return
		}
		code, src := cemi.LDataInd, tool
		if b[0]&1 != 0 {
			code = cemi.LDataReq
		}
		if b[0]&2 != 0 {
			src = knx.IndividualAddress(0x1105)
		}
		devTab, _ := datasecure.NewTable(nil, nil, 500)
		devTab.SetToolKey(dev, datasecure.Key{1, 2, 3})
		plain := &mgmt.Responder{Address: dev, Descriptor: 0x091A, Properties: &props{name: []byte("abcd")}}
		secured := &mgmt.Responder{Address: dev, Properties: &props{name: []byte("abcd")}, Security: devTab, Code: cemi.LDataReq}
		rest := b[1:]
		for n := 0; len(rest) > 0 && n < 32; n++ {
			l := int(rest[0])
			rest = rest[1:]
			if l > len(rest) {
				l = len(rest)
			}
			tpdu := append([]byte(nil), rest[:l]...)
			rest = rest[l:]
			if len(tpdu) == 0 {
				continue
			}
			fr := cemi.NewIndividualFrame(code, src, dev, knx.PrioritySystem, tpdu)
			for i, r := range []*mgmt.Responder{plain, secured} {
				out := r.Handle(fr.Clone())
				if len(out) > 2 {
					t.Fatalf("responder %d: %d answers to one frame", i, len(out))
				}
				for _, a := range out {
					if a == nil {
						t.Fatalf("responder %d: nil answer", i)
					}
					if a.Source != dev || knx.IndividualAddress(a.Destination) != src || a.IsGroup() {
						t.Fatalf("responder %d: answer %s to a frame from %s", i, a, src)
					}
					if _, err := cemi.Marshal(a); err != nil {
						t.Fatalf("responder %d: answer does not encode: %v", i, err)
					}
					if i == 0 {
						if _, err := apdu.Parse(a.TPDU); err != nil {
							t.Fatalf("plain answer % X: %v", a.TPDU, err)
						}
					}
				}
			}
		}
	})
}

// FuzzParseDescription decodes arbitrary A_PropertyDescription_Response
// data: nothing may panic, and a decoded description encodes to the same
// data except for the reserved bits and decodes to itself.
func FuzzParseDescription(f *testing.F) {
	f.Add([]byte{2, 76, 9, 0x82, 0x00, 0x1E, 0x31})
	f.Add([]byte{0, 11, 3, 0x16, 0x0A, 0xBC, 0xF0})
	f.Add([]byte{0, 50, 0, 0, 0, 0, 0})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	f.Add([]byte{0, 1, 2})
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := mgmt.ParseDescription(apdu.TPDU{APCI: apdu.PropertyDescriptionResponseService, Data: b})
		if err != nil {
			return
		}
		enc := d.Data()
		want := append([]byte(nil), b...)
		want[3] &^= 0x40
		want[4] &= 0x0F
		if !bytes.Equal(enc, want) {
			t.Fatalf("% X encodes as % X", b, enc)
		}
		back, err := mgmt.ParseDescription(apdu.TPDU{Data: enc})
		if err != nil || back != d {
			t.Fatalf("%+v: %+v %v", d, back, err)
		}
	})
}
