// SPDX-License-Identifier: MIT

package mgmt_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/datasecure"
	"github.com/otfabric/go-knx/mgmt"
)

var (
	dev  = knx.MustParseIndividualAddress("1.1.0")
	tool = knx.MustParseIndividualAddress("1.1.10")
)

// props has one object (index 0) with PID 11 (6 octets, read only) and
// PID 76 (writable, 4 elements of one octet).
type props struct{ name []byte }

func (p *props) ReadProperty(object, pid uint8, start uint16, count uint8) ([]byte, bool) {
	if object != 0 {
		return nil, false
	}
	switch {
	case pid == 11 && start == 1 && count == 1:
		return []byte{0, 0xFA, 1, 2, 3, 4}, true
	case pid == 76 && start == 0 && count == 1:
		return []byte{0, 4}, true
	case pid == 76 && start >= 1 && int(start)-1+int(count) <= len(p.name):
		return p.name[start-1 : int(start)-1+int(count)], true
	}
	return nil, false
}

func (p *props) WriteProperty(object, pid uint8, start uint16, count uint8, data []byte) bool {
	if object != 0 || pid != 76 || start == 0 || int(start)-1+int(count) > len(p.name) || len(data) != int(count) {
		return false
	}
	copy(p.name[start-1:], data)
	return true
}

func (p *props) DescribeProperty(object, pid, index uint8) (mgmt.Description, bool) {
	if object != 0 {
		return mgmt.Description{}, false
	}
	if pid == 0 {
		pid = map[uint8]uint8{0: 11, 1: 76}[index]
	}
	switch pid {
	case 11:
		return mgmt.Description{PID: 11, Index: 0, Type: 0x16, MaxElements: 1, Access: 0xF0}, true
	case 76:
		return mgmt.Description{PID: 76, Index: 1, Type: 0x02, Writable: true, MaxElements: 4, Access: 0xF0}, true
	}
	return mgmt.Description{}, false
}

func frame(t apdu.TPCI, svc apdu.APCI, data ...byte) *cemi.LData {
	return cemi.NewIndividualFrame(cemi.LDataInd, tool, dev, knx.PrioritySystem, apdu.TPDU{TPCI: t, APCI: svc, Data: data}.Bytes())
}

func control(t apdu.TPCI) *cemi.LData {
	return cemi.NewIndividualFrame(cemi.LDataInd, tool, dev, knx.PrioritySystem, apdu.TPDU{TPCI: t}.Bytes())
}

func parse(t *testing.T, f *cemi.LData) apdu.TPDU {
	t.Helper()
	if f.Source != dev || knx.IndividualAddress(f.Destination) != tool {
		t.Fatalf("answer %s", f)
	}
	p, err := apdu.Parse(f.TPDU)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

var data = apdu.TPCI{Kind: apdu.TData}

func TestConnectionless(t *testing.T) {
	r := &mgmt.Responder{Address: dev, Descriptor: 0x091A, Properties: &props{name: []byte("abcd")}}
	read := mgmt.Property{Object: 0, PID: 11, Start: 1, Count: 1}
	out := r.Handle(cemi.NewIndividualFrame(cemi.LDataInd, tool, dev, knx.PrioritySystem, read.TPDU(data, apdu.PropertyValueReadService)))
	if len(out) != 1 {
		t.Fatalf("%d answers", len(out))
	}
	p, err := mgmt.ParseProperty(parse(t, out[0]))
	if err != nil || p.Count != 1 || !bytes.Equal(p.Data, []byte{0, 0xFA, 1, 2, 3, 4}) {
		t.Fatalf("read %+v %v", p, err)
	}
	if out[0].MsgCode != cemi.LDataInd {
		t.Errorf("message code %v", out[0].MsgCode)
	}

	write := mgmt.Property{Object: 0, PID: 76, Start: 2, Count: 2, Data: []byte("XY")}
	out = r.Handle(cemi.NewIndividualFrame(cemi.LDataInd, tool, dev, knx.PrioritySystem, write.TPDU(data, apdu.PropertyValueWriteService)))
	if p, _ := mgmt.ParseProperty(parse(t, out[0])); p.Count != 2 || string(p.Data) != "XY" {
		t.Fatalf("write answer %+v", p)
	}
	// Refused: a read only property, a missing one (count 0).
	for _, req := range []struct {
		p   mgmt.Property
		svc apdu.APCI
	}{
		{mgmt.Property{PID: 11, Start: 1, Count: 1, Data: make([]byte, 6)}, apdu.PropertyValueWriteService},
		{mgmt.Property{PID: 99, Start: 1, Count: 1}, apdu.PropertyValueReadService},
	} {
		out = r.Handle(cemi.NewIndividualFrame(cemi.LDataInd, tool, dev, knx.PrioritySystem, req.p.TPDU(data, req.svc)))
		if p, _ := mgmt.ParseProperty(parse(t, out[0])); p.Count != 0 || p.PID != req.p.PID {
			t.Errorf("refusal %+v", p)
		}
	}

	out = r.Handle(frame(data, apdu.DeviceDescriptorReadService))
	if d := parse(t, out[0]); d.APCI != apdu.DeviceDescriptorResponseService || !bytes.Equal(d.Data, []byte{0x09, 0x1A}) {
		t.Fatalf("descriptor %+v", d)
	}
	out = r.Handle(cemi.NewIndividualFrame(cemi.LDataInd, tool, dev, knx.PrioritySystem, apdu.TPDU{TPCI: data, APCI: apdu.DeviceDescriptorReadService, Short: 2}.Bytes()))
	if d := parse(t, out[0]); d.Short != 0x3F {
		t.Fatalf("descriptor type 2 %+v", d)
	}

	// Descriptions: by PID, by index, missing.
	for _, c := range []struct {
		pid, index uint8
		want       []byte
	}{
		{76, 0, []byte{0, 76, 1, 0x82, 0, 4, 0xF0}},
		{0, 0, []byte{0, 11, 0, 0x16, 0, 1, 0xF0}},
		{50, 0, []byte{0, 50, 0, 0, 0, 0, 0}},
	} {
		out = r.Handle(frame(data, apdu.PropertyDescriptionReadService, 0, c.pid, c.index))
		if d := parse(t, out[0]); d.APCI != apdu.PropertyDescriptionResponseService || !bytes.Equal(d.Data, c.want) {
			t.Errorf("description %d/%d: % X", c.pid, c.index, d.Data)
		}
	}

	// Not answered: other destinations, group frames, own frames,
	// unknown services, malformed property requests.
	other := frame(data, apdu.DeviceDescriptorReadService)
	other.Destination = uint16(knx.MustParseIndividualAddress("1.1.1"))
	own := frame(data, apdu.DeviceDescriptorReadService)
	own.Source = dev
	for _, f := range []*cemi.LData{other, own,
		cemi.NewGroupFrame(cemi.LDataInd, tool, 1, knx.PriorityLow, []byte{0, 0}),
		frame(data, apdu.RestartService),
		frame(data, apdu.PropertyValueReadService, 0),
		frame(data, apdu.PropertyDescriptionReadService, 0),
		cemi.NewIndividualFrame(cemi.LDataInd, tool, dev, knx.PrioritySystem, []byte{0x80, 0x00}),
	} {
		if out := r.Handle(f); out != nil {
			t.Errorf("answer to %s", f)
		}
	}
}

func TestConnection(t *testing.T) {
	r := &mgmt.Responder{Address: dev, Descriptor: 0x07B0, Properties: &props{name: []byte("abcd")}, Code: cemi.LDataReq}
	if out := r.Handle(control(apdu.TPCI{Kind: apdu.TConnect})); out != nil {
		t.Fatalf("connect answered %v", out)
	}
	// Data in the connection: acknowledged, then answered with the
	// responder's own sequence number.
	out := r.Handle(frame(apdu.TPCI{Kind: apdu.TDataConnected, Seq: 0}, apdu.DeviceDescriptorReadService))
	if len(out) != 2 || out[0].MsgCode != cemi.LDataReq {
		t.Fatalf("%d answers", len(out))
	}
	if a := parse(t, out[0]); a.TPCI != (apdu.TPCI{Kind: apdu.TAck, Seq: 0}) {
		t.Fatalf("ack %+v", a.TPCI)
	}
	if a := parse(t, out[1]); a.TPCI != (apdu.TPCI{Kind: apdu.TDataConnected, Seq: 0}) || a.APCI != apdu.DeviceDescriptorResponseService {
		t.Fatalf("answer %+v", a)
	}
	r.Handle(control(apdu.TPCI{Kind: apdu.TAck, Seq: 0}))
	// A repetition is acknowledged again, not answered.
	if out := r.Handle(frame(apdu.TPCI{Kind: apdu.TDataConnected, Seq: 0}, apdu.DeviceDescriptorReadService)); len(out) != 1 || parse(t, out[0]).TPCI.Kind != apdu.TAck {
		t.Fatalf("repetition %v", out)
	}
	out = r.Handle(frame(apdu.TPCI{Kind: apdu.TDataConnected, Seq: 1}, apdu.DeviceDescriptorReadService))
	if len(out) != 2 || parse(t, out[1]).TPCI != (apdu.TPCI{Kind: apdu.TDataConnected, Seq: 1}) {
		t.Fatalf("second answer %v", out)
	}
	// A second tool is refused while the connection is open.
	stranger := control(apdu.TPCI{Kind: apdu.TConnect})
	stranger.Source = knx.MustParseIndividualAddress("1.1.11")
	if out := r.Handle(stranger); len(out) != 1 || knx.IndividualAddress(out[0].Destination) != stranger.Source {
		t.Fatalf("stranger %v", out)
	}
	// A wrong sequence number ends the connection; data outside one is
	// refused with T_Disconnect.
	if out := r.Handle(frame(apdu.TPCI{Kind: apdu.TDataConnected, Seq: 7}, apdu.DeviceDescriptorReadService)); len(out) != 1 || parse(t, out[0]).TPCI.Kind != apdu.TDisconnect {
		t.Fatalf("wrong sequence %v", out)
	}
	if out := r.Handle(frame(apdu.TPCI{Kind: apdu.TDataConnected, Seq: 0}, apdu.DeviceDescriptorReadService)); len(out) != 1 || parse(t, out[0]).TPCI.Kind != apdu.TDisconnect {
		t.Fatalf("data without connection %v", out)
	}
	// Connect, disconnect: data is refused again.
	r.Handle(control(apdu.TPCI{Kind: apdu.TConnect}))
	r.Handle(control(apdu.TPCI{Kind: apdu.TNak, Seq: 0}))
	r.Handle(control(apdu.TPCI{Kind: apdu.TDisconnect}))
	if out := r.Handle(frame(apdu.TPCI{Kind: apdu.TDataConnected, Seq: 0}, apdu.DeviceDescriptorReadService)); len(out) != 1 || parse(t, out[0]).TPCI.Kind != apdu.TDisconnect {
		t.Fatalf("data after disconnect %v", out)
	}
}

func TestSecured(t *testing.T) {
	key := datasecure.Key{1, 2, 3}
	devTab, _ := datasecure.NewTable(nil, nil, 500)
	devTab.SetToolKey(dev, key)
	r := &mgmt.Responder{Address: dev, Properties: &props{name: []byte("abcd")}, Security: devTab}
	toolTab, _ := datasecure.NewTable(nil, nil, 10)
	toolTab.SetToolKey(dev, key)

	// Plain access is not answered.
	if out := r.Handle(frame(data, apdu.DeviceDescriptorReadService)); out != nil {
		t.Fatalf("plain access answered")
	}
	for _, connected := range []bool{false, true} {
		tpci := data
		if connected {
			r.Handle(control(apdu.TPCI{Kind: apdu.TConnect}))
			tpci = apdu.TPCI{Kind: apdu.TDataConnected}
		}
		answer := func(f *cemi.LData) *cemi.LData {
			t.Helper()
			out := r.Handle(f)
			if connected {
				if len(out) != 2 {
					t.Fatalf("%d answers", len(out))
				}
				r.Handle(control(apdu.TPCI{Kind: apdu.TAck, Seq: parse(t, out[1]).TPCI.Seq}))
				tpci.Seq++
				return out[1]
			}
			if len(out) != 1 {
				t.Fatalf("%d answers", len(out))
			}
			return out[0]
		}
		req, challenge, err := toolTab.SyncRequest(cemi.LDataInd, tool, dev, tpci.Octet())
		if err != nil {
			t.Fatal(err)
		}
		if err := toolTab.OpenSyncResponse(answer(req), challenge); err != nil {
			t.Fatalf("sync: %v", err)
		}
		p := mgmt.Property{Object: 0, PID: 11, Start: 1, Count: 1}
		sealed, err := toolTab.SealToolRequest(cemi.NewIndividualFrame(cemi.LDataInd, tool, dev, knx.PrioritySystem, p.TPDU(tpci, apdu.PropertyValueReadService)))
		if err != nil {
			t.Fatal(err)
		}
		res := answer(sealed)
		plain, err := toolTab.OpenToolResponse(res)
		if err != nil {
			t.Fatalf("answer: %v", err)
		}
		if got, _ := mgmt.ParseProperty(parse(t, plain)); !bytes.Equal(got.Data, []byte{0, 0xFA, 1, 2, 3, 4}) {
			t.Fatalf("secured read %+v", got)
		}
		// The device's answer is not accepted twice.
		if _, err := toolTab.OpenToolResponse(res); !errors.Is(err, knx.ErrSecurity) {
			t.Errorf("replayed answer: %v", err)
		}
		// A replayed request is not answered.
		if out := r.Handle(sealed); len(out) > 1 || (len(out) == 1 && parse(t, out[0]).TPCI.Kind != apdu.TAck) {
			t.Errorf("replayed request answered: %v", out)
		}
		if connected {
			r.Handle(control(apdu.TPCI{Kind: apdu.TDisconnect}))
		}
	}

	// Tool side errors: no key, plain or group frames, no tool access.
	none, _ := datasecure.NewTable(nil, nil, 1)
	if _, _, err := none.SyncRequest(cemi.LDataInd, tool, dev, 0); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("sync without key: %v", err)
	}
	if _, err := none.SealToolRequest(frame(data, apdu.DeviceDescriptorReadService)); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("seal without key: %v", err)
	}
	devAnswer, _ := devTab.SealTool(cemi.NewIndividualFrame(cemi.LDataInd, dev, tool, knx.PrioritySystem, []byte{0x03, 0x40, 0, 1}))
	if _, err := none.OpenToolResponse(devAnswer); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("open without key: %v", err)
	}
	if err := none.OpenSyncResponse(devAnswer, [6]byte{}); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("sync response without key: %v", err)
	}
	if _, err := toolTab.OpenToolResponse(frame(data, apdu.DeviceDescriptorReadService)); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("plain answer: %v", err)
	}
	grp, _ := datasecure.Seal(key, cemi.NewIndividualFrame(cemi.LDataInd, dev, tool, knx.PrioritySystem, []byte{0x03, 0x40, 0, 1}), 9000, datasecure.GroupData)
	if _, err := toolTab.OpenToolResponse(grp); !errors.Is(err, knx.ErrSecurity) {
		t.Errorf("answer without tool access: %v", err)
	}
	if _, ok := toolTab.ToolKey(dev); !ok {
		t.Error("ToolKey")
	}
}

func TestPropertyError(t *testing.T) {
	e := &mgmt.PropertyError{Device: dev, Object: 2, PID: 76}
	if !errors.Is(e, knx.ErrRejected) || e.Error() != "mgmt: 1.1.0 refused object 2 property 76" {
		t.Errorf("%v", e)
	}
	if _, err := mgmt.ParseProperty(apdu.TPDU{APCI: apdu.PropertyValueReadService, Data: []byte{1}}); !errors.Is(err, knx.ErrMalformed) {
		t.Errorf("short property: %v", err)
	}
}

// TestRepeat: an answer in a transport connection that the peer does not
// acknowledge is repeated after 3 s, unchanged, at most three times; then
// the connection ends. An acknowledged answer is not repeated.
func TestRepeat(t *testing.T) {
	r := &mgmt.Responder{Address: dev, Descriptor: 0x091A, Properties: &props{name: []byte("abcd")}}
	read := func(seq uint8) *cemi.LData {
		t.Helper()
		out := r.Handle(frame(apdu.TPCI{Kind: apdu.TDataConnected, Seq: seq}, apdu.DeviceDescriptorReadService))
		if len(out) != 2 {
			t.Fatalf("%d frames, want T_Ack and answer", len(out))
		}
		return out[1]
	}
	if len(r.Handle(control(apdu.TPCI{Kind: apdu.TConnect}))) != 0 {
		t.Fatal("answer to T_Connect")
	}
	// Times are taken after Handle: Repeat measures from the send time.
	answer := read(0)
	now := time.Now()
	if f := r.Repeat(now.Add(2 * time.Second)); f != nil {
		t.Fatalf("repeated before 3 s: %v", f)
	}
	for i := 1; i <= 3; i++ {
		now = now.Add(3*time.Second + 100*time.Millisecond)
		f := r.Repeat(now)
		if len(f) != 1 || f[0].String() != answer.String() {
			t.Fatalf("repetition %d: %v, want %v", i, f, answer)
		}
	}
	now = now.Add(3*time.Second + 100*time.Millisecond)
	f := r.Repeat(now)
	if len(f) != 1 || parse(t, f[0]).TPCI.Kind != apdu.TDisconnect {
		t.Fatalf("after three repetitions: %v, want T_Disconnect", f)
	}
	if f := r.Repeat(now.Add(10 * time.Second)); f != nil {
		t.Fatalf("after the disconnect: %v", f)
	}

	// Acknowledged: nothing to repeat; the next answer has the next number.
	r.Handle(control(apdu.TPCI{Kind: apdu.TConnect}))
	read(0)
	r.Handle(control(apdu.TPCI{Kind: apdu.TAck, Seq: 0}))
	if f := r.Repeat(time.Now().Add(4 * time.Second)); f != nil {
		t.Fatalf("acknowledged answer repeated: %v", f)
	}
	if a := parse(t, read(1)); a.TPCI.Seq != 1 {
		t.Fatalf("next answer numbered %d", a.TPCI.Seq)
	}
	// A T_NAK of the pending answer repeats it at once, three times; the
	// fourth ends the connection. A T_NAK of another number is ignored.
	r.Handle(control(apdu.TPCI{Kind: apdu.TAck, Seq: 1}))
	pending := read(2)
	if a := parse(t, pending); a.TPCI.Seq != 2 {
		t.Fatalf("answer numbered %d", a.TPCI.Seq)
	}
	if f := r.Handle(control(apdu.TPCI{Kind: apdu.TNak, Seq: 1})); f != nil {
		t.Fatalf("T_NAK of another number: %v", f)
	}
	for i := 1; i <= 3; i++ {
		f := r.Handle(control(apdu.TPCI{Kind: apdu.TNak, Seq: 2}))
		if len(f) != 1 || f[0].String() != pending.String() {
			t.Fatalf("T_NAK %d: %v, want %v", i, f, pending)
		}
	}
	if f := r.Handle(control(apdu.TPCI{Kind: apdu.TNak, Seq: 2})); len(f) != 1 || parse(t, f[0]).TPCI.Kind != apdu.TDisconnect {
		t.Fatalf("fourth T_NAK: %v, want T_Disconnect", f)
	}
	r.Handle(control(apdu.TPCI{Kind: apdu.TConnect}))
	read(0)
	// A T_Disconnect of the peer drops the pending answer.
	r.Handle(control(apdu.TPCI{Kind: apdu.TDisconnect}))
	if f := r.Repeat(time.Now().Add(4 * time.Second)); f != nil {
		t.Fatalf("answer repeated after T_Disconnect: %v", f)
	}
	// Connectionless answers are never repeated.
	r.Handle(frame(data, apdu.DeviceDescriptorReadService))
	if f := r.Repeat(time.Now().Add(4 * time.Second)); f != nil {
		t.Fatalf("connectionless answer repeated: %v", f)
	}
}

// TestSecuredSyncReplay: a recorded S-A_Sync_Req and the property write
// that followed it, sent again after a later write, are refused: the value
// stays the later one. The write alone is refused as well. Both the
// library's tool side and a tool that reuses the request's sequence number
// for its first frame (Calimero) are covered.
func TestSecuredSyncReplay(t *testing.T) {
	key := datasecure.Key{1, 2, 3}
	devTab, _ := datasecure.NewTable(nil, nil, 500)
	devTab.SetToolKey(dev, key)
	p := &props{name: []byte("abcd")}
	r := &mgmt.Responder{Address: dev, Properties: p, Security: devTab}
	toolTab, _ := datasecure.NewTable(nil, nil, 10)
	toolTab.SetToolKey(dev, key)
	write := func(val string) *cemi.LData {
		w := mgmt.Property{Object: 0, PID: 76, Start: 1, Count: 4, Data: []byte(val)}
		return cemi.NewIndividualFrame(cemi.LDataInd, tool, dev, knx.PrioritySystem, w.TPDU(data, apdu.PropertyValueWriteService))
	}
	library := func(val string) (*cemi.LData, *cemi.LData) {
		t.Helper()
		req, ch, err := toolTab.SyncRequest(cemi.LDataInd, tool, dev, 0)
		if err != nil {
			t.Fatal(err)
		}
		out := r.Handle(req)
		if len(out) != 1 || toolTab.OpenSyncResponse(out[0], ch) != nil {
			t.Fatalf("sync %q failed", val)
		}
		sealed, err := toolTab.SealToolRequest(write(val))
		if err != nil {
			t.Fatal(err)
		}
		if out := r.Handle(sealed); len(out) != 1 {
			t.Fatalf("write %q not answered", val)
		}
		return req, sealed
	}
	calimero := func(val string) (*cemi.LData, *cemi.LData) {
		t.Helper()
		seq := toolTab.Sequence()
		ch := [6]byte{4, 5, 6}
		req, _ := datasecure.SyncRequest(key, cemi.LDataInd, tool, dev, 0, seq, [6]byte{}, ch)
		if out := r.Handle(req); len(out) != 1 {
			t.Fatalf("sync %q failed", val)
		}
		sealed, _ := datasecure.Seal(key, write(val), seq, datasecure.SCF{ToolAccess: true, Algorithm: datasecure.AuthConf})
		if out := r.Handle(sealed); len(out) != 1 {
			t.Fatalf("write %q not answered", val)
		}
		_, _ = toolTab.SealToolRequest(write("skip")) // move the tool's sequence on
		return req, sealed
	}
	for name, session := range map[string]func(string) (*cemi.LData, *cemi.LData){"library": library, "calimero": calimero} {
		recSync, recWrite := session("OLD ")
		session("NEW ")
		if out := r.Handle(recWrite.Clone()); out != nil {
			t.Errorf("%s: repeated write answered", name)
		}
		if out := r.Handle(recSync.Clone()); len(out) != 1 {
			t.Errorf("%s: repeated sync request: %d answers", name, len(out))
		}
		if out := r.Handle(recWrite.Clone()); out != nil {
			t.Errorf("%s: write after repeated sync answered", name)
		}
		if string(p.name) != "NEW " {
			t.Errorf("%s: value %q, want %q", name, p.name, "NEW ")
		}
	}
}
