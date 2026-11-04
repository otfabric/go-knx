// SPDX-License-Identifier: MIT

package datasecure

import (
	"bytes"
	"testing"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
)

var (
	fuzzSender = knx.IndividualAddress(0x1101) // 1.1.1
	fuzzDevice = knx.IndividualAddress(0x1100) // 1.1.0
	fuzzGroup  = knx.GroupAddress(0x0a03)      // 1/2/3
	fuzzTool   = Key{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01}
)

// FuzzIncoming feeds arbitrary cEMI frames to the receiving side of Data
// Secure: Open, Table.Incoming, Table.OpenTool, Table.Respond (S-A_Sync_Req)
// and OpenSyncRequest. Nothing may panic; a frame that opens must be one the
// key holder produced (sealing its plain frame again with the same
// sequence number and SCF gives the same S-A_Data), and a frame accepted by
// a table must not be accepted twice (replay).
func FuzzIncoming(f *testing.F) {
	w, _ := apdu.GroupValueWrite(apdu.GroupValue{Small: true, Data: []byte{1}})
	plain := cemi.NewGroupFrame(cemi.LDataInd, fuzzSender, fuzzGroup, knx.PriorityLow, w)
	add := func(fr *cemi.LData) {
		b, err := cemi.Marshal(fr)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	add(plain)
	for i, scf := range []SCF{GroupData, {Algorithm: AuthOnly}, {ToolAccess: true, Algorithm: AuthConf}} {
		s, err := Seal(key040, plain, uint64(100+i), scf)
		if err != nil {
			f.Fatal(err)
		}
		add(s)
	}
	toolReq := cemi.NewIndividualFrame(cemi.LDataInd, fuzzSender, fuzzDevice, knx.PrioritySystem,
		apdu.TPDU{APCI: apdu.DeviceDescriptorReadService}.Bytes())
	if s, err := Seal(fuzzTool, toolReq, 7, SCF{ToolAccess: true, Algorithm: AuthConf}); err == nil {
		add(s)
	}
	if req, err := SyncRequest(fuzzTool, cemi.LDataInd, fuzzSender, fuzzDevice, 0, 9, [6]byte{0, 0xfa}, [6]byte{1, 2, 3, 4, 5, 6}); err == nil {
		add(req)
	}
	if res, err := SyncResponse(fuzzTool, cemi.LDataInd, fuzzDevice, fuzzSender, 0, [6]byte{1, 2, 3, 4, 5, 6}, [6]byte{6, 5, 4}, 50, 60); err == nil {
		add(res)
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		fr, err := cemi.Parse(b)
		if err != nil {
			return
		}
		ld, ok := fr.(*cemi.LData)
		if !ok {
			return
		}
		orig := append([]byte(nil), ld.TPDU...)
		if p, seq, scf, err := Open(key040, ld); err == nil {
			again, err := Seal(key040, p, seq, scf)
			if err != nil {
				t.Fatalf("an opened frame does not seal again: %v", err)
			}
			if !bytes.Equal(again.TPDU, ld.TPDU) {
				t.Fatalf("opened an S-A_Data Seal does not produce:\n% X\n% X", ld.TPDU, again.TPDU)
			}
		}
		if !bytes.Equal(orig, ld.TPDU) {
			t.Fatal("Open modified its input")
		}

		tab, err := NewTable(map[knx.GroupAddress]Key{fuzzGroup: key040}, map[knx.IndividualAddress]uint64{fuzzSender: 1, ld.Source: 1}, 1000)
		if err != nil {
			t.Fatal(err)
		}
		tab.SetToolKey(fuzzDevice, fuzzTool)
		if out, err := tab.Incoming(ld); err == nil && IsSecure(ld) {
			if out == nil {
				t.Fatal("nil frame without error")
			}
			if _, err := tab.Incoming(ld); err == nil {
				t.Fatal("a secured telegram was accepted twice")
			}
		}
		if out, err := tab.OpenTool(ld, fuzzDevice); err == nil && out != nil {
			if again, err := tab.OpenTool(ld, fuzzDevice); err == nil && again != nil {
				t.Fatal("a tool access was accepted twice")
			}
		}
		if res, err := tab.Respond(ld, fuzzDevice, cemi.LDataReq); err == nil && res != nil {
			if _, err := cemi.Marshal(res); err != nil {
				t.Fatalf("S-A_Sync_Res does not encode: %v", err)
			}
		}
		_, _ = OpenSyncRequest(fuzzTool, ld)
		_, _, _ = OpenSyncResponse(fuzzTool, ld, [6]byte{1, 2, 3, 4, 5, 6})
	})
}
