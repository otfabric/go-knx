// SPDX-License-Identifier: MIT

package mgmt

import (
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
)

// TestConnectionTimeoutDropsPending checks that a transport connection idle
// for longer than the connection timeout ends, together with the answer
// still awaiting its T_Ack: nothing is repeated after it.
func TestConnectionTimeoutDropsPending(t *testing.T) {
	dev := knx.MustParseIndividualAddress("1.1.0")
	tool := knx.MustParseIndividualAddress("1.1.10")
	in := func(p apdu.TPDU) *cemi.LData {
		return cemi.NewIndividualFrame(cemi.LDataInd, tool, dev, knx.PrioritySystem, p.Bytes())
	}
	r := &Responder{Address: dev, Descriptor: 0x091A}
	r.Handle(in(apdu.TPDU{TPCI: apdu.TPCI{Kind: apdu.TConnect}}))
	if out := r.Handle(in(apdu.TPDU{TPCI: apdu.TPCI{Kind: apdu.TDataConnected}, APCI: apdu.DeviceDescriptorReadService})); len(out) != 2 {
		t.Fatalf("%d frames, want T_Ack and answer", len(out))
	}

	r.mu.Lock()
	r.last = r.last.Add(-connectionTimeout - time.Second)
	r.mu.Unlock()
	// Any frame for the device notices the timeout. A T_Data_Connected of
	// the ended connection gets a T_Disconnect, not an answer.
	out := r.Handle(in(apdu.TPDU{TPCI: apdu.TPCI{Kind: apdu.TDataConnected, Seq: 1}, APCI: apdu.DeviceDescriptorReadService}))
	if len(out) != 1 {
		t.Fatalf("after the connection timeout: %v, want T_Disconnect", out)
	}
	if p, err := apdu.Parse(out[0].TPDU); err != nil || p.TPCI.Kind != apdu.TDisconnect {
		t.Fatalf("after the connection timeout: %v (%v), want T_Disconnect", out, err)
	}
	if f := r.Repeat(time.Now().Add(4 * time.Second)); f != nil {
		t.Fatalf("repetition after the connection timeout: %v", f)
	}
}
