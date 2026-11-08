// SPDX-License-Identifier: MIT

package mgmt_test

import (
	"bytes"
	"encoding/binary"
	"maps"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/internal/capture"
	"github.com/otfabric/go-knx/mgmt"
)

// attacker is the individual address the knx-datasets line scan and
// device-info runs used (README: a compromised switch).
var attacker = knx.MustParseIndividualAddress("1.1.102")

var recordedConversations = []string{
	"knx-datasets/attack-tool_residential-tp1_line-scan.pcapng",
	"knx-datasets/attack-tool_residential-tp1_device-info.pcapng",
}

// TestCaptureResponderReplay sends every request the management client
// sent to the devices of a real TP1 installation to a Responder standing
// in for each device, and compares its answers with the device's recorded
// answers, TPDU for TPDU (sequence numbers included). The descriptor is
// the device's own recorded one. Hop counts are not compared: the
// devices sit behind line couplers that change them.
//
// Classified differences (counts pinned):
//   - unsupported: A_Memory_Read and A_ADC_Read, which the Responder does
//     not serve; it acknowledges them (T_ACK) and sends no answer.
//   - repeated: a link-layer repetition of a T_Data_Connected (repeat
//     flag, same octets). The devices answered each request once: their
//     data link layer took the repetitions for the frame already
//     received. The Responder, which has no TP1 data link layer, takes a
//     repeated sequence number as the transport layer does and
//     acknowledges it again.
//   - timeout: the device ended an idle connection; the Responder does
//     that in Repeat, compared by TestCaptureConnectionTimeout.
//
// "silent" exchanges are those neither side answers (T_Connect, T_ACK,
// T_Disconnect of the client; addresses without a device in the scan).
func TestCaptureResponderReplay(t *testing.T) {
	want := map[string]map[string]int{
		recordedConversations[0]: {"equal": 25, "repeated": 30, "silent": 343, "timeout": 75},
		recordedConversations[1]: {"silent": 990, "unsupported": 720, "repeated": 90},
	}
	for _, file := range recordedConversations {
		t.Run(file, func(t *testing.T) {
			f, err := capture.Load(file)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]int{}
			devices := map[knx.IndividualAddress]*mgmt.Responder{}
			descriptors := recordedDescriptors(f)
			for _, ex := range capture.Exchanges(f.TP, attacker) {
				r := devices[ex.Device]
				if r == nil {
					r = &mgmt.Responder{Address: ex.Device, Descriptor: descriptors[ex.Device]}
					devices[ex.Device] = r
				}
				in := ex.Request.Clone()
				in.MsgCode = cemi.LDataInd
				out := r.Handle(in)
				// The link-layer repetitions, as the recording has them.
				var again []*cemi.LData
				for range ex.Repeats {
					rep := in.Clone()
					rep.Ctrl1 &^= cemi.Ctrl1NoRepeat
					again = append(again, r.Handle(rep)...)
				}
				got[classify(t, ex, out, again)]++
			}
			if !maps.Equal(got, want[file]) {
				t.Errorf("exchanges %v, want %v", got, want[file])
			}
			t.Logf("%d devices, exchanges %v", len(devices), got)
		})
	}
}

// classify compares the Responder's answers with the device's.
func classify(t *testing.T, ex capture.Exchange, out, again []*cemi.LData) string {
	t.Helper()
	req := mustParse(t, ex.Request)
	rec := ex.Answers
	if len(rec) == 1 && len(out) == 0 && mustParse(t, rec[0]).TPCI.Kind == apdu.TDisconnect && req.TPCI.Kind == apdu.TConnect {
		return "timeout"
	}
	for _, a := range out {
		if a.Source != ex.Device || knx.IndividualAddress(a.Destination) != attacker || a.Priority() != knx.PrioritySystem {
			t.Errorf("%s: answer %s", ex.Request, a)
		}
	}
	if len(again) > 0 {
		// Every repetition of a numbered data PDU is acknowledged again.
		for _, a := range again {
			if p := mustParse(t, a); p.TPCI.Kind != apdu.TAck || p.TPCI.Seq != req.TPCI.Seq || req.TPCI.Kind != apdu.TDataConnected {
				t.Errorf("%s: answer to a repetition %s", ex.Request, a)
			}
		}
		if len(again) != ex.Repeats {
			t.Errorf("%s: %d answers to %d repetitions", ex.Request, len(again), ex.Repeats)
		}
	}
	if req.APCI == apdu.MemoryReadService || req.APCI == apdu.ADCReadService {
		if len(out) != 1 || len(rec) != 2 || !bytes.Equal(out[0].TPDU, rec[0].TPDU) {
			t.Errorf("%s: answers %v, recorded %v", ex.Request, out, rec)
		}
		return "unsupported"
	}
	if len(out) == 0 && len(rec) == 0 && len(again) == 0 {
		return "silent"
	}
	if len(out) != len(rec) {
		t.Errorf("%s: answers %v, recorded %v", ex.Request, out, rec)
		return "different"
	}
	for i := range out {
		if !bytes.Equal(out[i].TPDU, rec[i].TPDU) || out[i].Priority() != rec[i].Priority() {
			t.Errorf("%s: answer %d %s, recorded %s", ex.Request, i, out[i], rec[i])
		}
	}
	if len(again) > 0 {
		return "repeated"
	}
	return "equal"
}

func mustParse(t *testing.T, f *cemi.LData) apdu.TPDU {
	t.Helper()
	p, err := apdu.Parse(f.TPDU)
	if err != nil {
		t.Fatalf("%s: %v", f, err)
	}
	return p
}

// recordedDescriptors returns the device descriptor each device answered.
func recordedDescriptors(f *capture.File) map[knx.IndividualAddress]uint16 {
	d := map[knx.IndividualAddress]uint16{}
	for _, fr := range f.TP {
		ld, err := cemi.ParseTP1(fr.Data)
		if err != nil || ld.IsGroup() {
			continue
		}
		if p, err := apdu.Parse(ld.TPDU); err == nil && p.APCI == apdu.DeviceDescriptorResponseService && len(p.Data) == 2 {
			d[ld.Source] = binary.BigEndian.Uint16(p.Data)
		}
	}
	return d
}

// TestCaptureConnectionTimeout: in the line scan, 75 devices ended a
// transport connection that the client opened (T_Connect) and left idle,
// with a T_Disconnect of their own 5 to 13 s after the client's first
// T_Connect (bus load delays some). The Responder ends an idle connection
// after 6 s the same way; it used to drop the connection silently. Six
// devices disconnected between 5.0 and 6.0 s: timer granularity, pinned
// (the Responder is checked at 6.1 s for them).
func TestCaptureConnectionTimeout(t *testing.T) {
	f, err := capture.Load(recordedConversations[0])
	if err != nil {
		t.Fatal(err)
	}
	early, n := 0, 0
	for _, ex := range capture.Exchanges(f.TP, attacker) {
		if len(ex.Answers) != 1 || mustParse(t, ex.Request).TPCI.Kind != apdu.TConnect {
			continue
		}
		rec := ex.Answers[0]
		if mustParse(t, rec).TPCI.Kind != apdu.TDisconnect {
			continue
		}
		n++
		delay := ex.Times[0].Sub(ex.Time)
		if delay < 6*time.Second {
			t.Logf("%s disconnected after %v", ex.Device, delay)
			early++
			delay = 6*time.Second + 100*time.Millisecond
		}
		r := &mgmt.Responder{Address: ex.Device}
		in := ex.Request.Clone()
		in.MsgCode = cemi.LDataInd
		now := time.Now()
		if out := r.Handle(in); out != nil {
			t.Fatalf("%s: answer to T_Connect %v", ex.Device, out)
		}
		if out := r.Repeat(now.Add(5 * time.Second)); out != nil {
			t.Fatalf("%s: %v after 5 s", ex.Device, out)
		}
		out := r.Repeat(now.Add(delay + 100*time.Millisecond))
		if len(out) != 1 || !bytes.Equal(out[0].TPDU, rec.TPDU) || out[0].Priority() != rec.Priority() ||
			out[0].Source != rec.Source || out[0].Destination != rec.Destination {
			t.Fatalf("%s after %v: %v, recorded %s", ex.Device, delay, out, rec)
		}
		if out := r.Repeat(now.Add(20 * time.Second)); out != nil {
			t.Fatalf("%s: %v after the disconnect", ex.Device, out)
		}
	}
	if n != 75 || early != 6 {
		t.Fatalf("%d device disconnects (%d before 6 s), want 75 (6)", n, early)
	}
	t.Logf("%d recorded device disconnects reproduced", n)
}
