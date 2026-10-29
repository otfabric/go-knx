// SPDX-License-Identifier: MIT

package device_test

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/device"
)

var (
	devAddr = knx.MustParseIndividualAddress("1.1.1")
	other   = knx.MustParseIndividualAddress("1.1.9")
	ga      = knx.MustParseGroupAddress("1/2/3")
	ga2     = knx.MustParseGroupAddress("1/2/4")
)

func TestParseFlags(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want device.Flags
		str  string
	}{
		{"", 0, ""},
		{"C", device.FlagCommunication, "C"},
		{"crwtui", device.FlagCommunication | device.FlagRead | device.FlagWrite | device.FlagTransmit | device.FlagUpdate | device.FlagReadOnInit, "CRWTUI"},
		{"WTC", device.FlagCommunication | device.FlagWrite | device.FlagTransmit, "CWT"},
		{"UR", device.FlagRead | device.FlagUpdate, "RU"},
	} {
		f, err := device.ParseFlags(tc.in)
		if err != nil || f != tc.want || f.String() != tc.str {
			t.Errorf("ParseFlags(%q) = %v (%q), %v; want %v (%q)", tc.in, f, f.String(), err, tc.want, tc.str)
		}
	}
	if _, err := device.ParseFlags("CX"); !errors.Is(err, knx.ErrInvalidOption) {
		t.Fatalf("bad flag: %v", err)
	}
}

func TestNewGroupObject(t *testing.T) {
	o, err := device.NewGroupObject("t", "9.001", "CRT", "1/2/3", "1/2/4")
	if err != nil {
		t.Fatal(err)
	}
	if o.SendingAddress() != ga || !o.Has(ga2) || o.Has(knx.MustParseGroupAddress("1/2/5")) {
		t.Fatalf("addresses %v", o.Addresses)
	}
	if _, ok, err := o.Value(); ok || err != nil {
		t.Fatalf("value before set: %v %v", ok, err)
	}
	if _, set := o.Raw(); set {
		t.Fatal("raw set")
	}
	for name, args := range map[string][]string{
		"dpt":     {"x", "99.999", "C", "1/2/3"},
		"flags":   {"x", "1.001", "Q", "1/2/3"},
		"address": {"x", "1.001", "C"},
		"group":   {"x", "1.001", "C", "99/99/99"},
	} {
		if _, err := device.NewGroupObject(args[0], args[1], args[2], args[3:]...); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if err := o.Set("not a number"); err == nil {
		t.Fatal("Set of a string in a 9.001 object")
	}
	if err := o.SetRaw([]byte{1}); err == nil {
		t.Fatal("SetRaw of one octet in a 9.001 object")
	}
	if err := o.Set(21.5); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := o.Value(); !ok || err != nil || v != 21.5 {
		t.Fatalf("value %v %v %v", v, ok, err)
	}
}

func mustObject(t *testing.T, name, id, flags string, addrs ...string) *device.GroupObject {
	t.Helper()
	o, err := device.NewGroupObject(name, id, flags, addrs...)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func frame(t *testing.T, src knx.IndividualAddress, g knx.GroupAddress, tpdu []byte) *cemi.LData {
	t.Helper()
	return cemi.NewGroupFrame(cemi.LDataInd, src, g, knx.PriorityNormal, tpdu)
}

func write(t *testing.T, v apdu.GroupValue) []byte {
	t.Helper()
	b, err := apdu.GroupValueWrite(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func response(t *testing.T, v apdu.GroupValue) []byte {
	t.Helper()
	b, err := apdu.GroupValueResponse(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDeviceObjects(t *testing.T) {
	d := device.New("dev", devAddr)
	a := mustObject(t, "a", "1.001", "C", "1/2/3")
	b := mustObject(t, "b", "1.001", "C", "1/2/4")
	if d.Add(a).Add(b) != d {
		t.Fatal("Add does not chain")
	}
	if objs := d.Objects(); len(objs) != 2 || objs[0] != a {
		t.Fatalf("objects %v", objs)
	}
	if o, ok := d.Object("b"); !ok || o != b {
		t.Fatal("Object(b)")
	}
	if _, ok := d.Object("c"); ok {
		t.Fatal("Object(c)")
	}
}

func TestReadAnsweredOnce(t *testing.T) {
	d := device.New("dev", devAddr)
	unset := mustObject(t, "unset", "9.001", "CR", "1/2/3")
	noR := mustObject(t, "noR", "9.001", "C", "1/2/3")
	first := mustObject(t, "first", "9.001", "CR", "1/2/4", "1/2/3")
	second := mustObject(t, "second", "9.001", "CR", "1/2/3")
	_ = noR.Set(1.0)
	_ = first.Set(20.0)
	_ = second.Set(30.0)
	d.Add(unset, noR, first, second)

	out := d.Handle(frame(t, other, ga, apdu.GroupValueRead()))
	if len(out) != 1 {
		t.Fatalf("%d responses, want 1", len(out))
	}
	r := out[0]
	g, _ := r.Group()
	if r.Source != devAddr || g != ga || r.MsgCode != cemi.LDataInd || r.Priority() != knx.PriorityNormal {
		t.Fatalf("response %v", r)
	}
	svc, v, err := apdu.ParseGroupValue(r.TPDU)
	if err != nil || svc != apdu.GroupValueResponseService {
		t.Fatalf("service %v %v", svc, err)
	}
	if got, _ := first.Type.Decode(v.Data); got != 20.0 {
		t.Fatalf("value %v", got)
	}
	// No object with a value: no answer. Other groups: none.
	if out := d.Handle(frame(t, other, knx.MustParseGroupAddress("5/5/5"), apdu.GroupValueRead())); out != nil {
		t.Fatalf("answer for an unknown group: %v", out)
	}
	d2 := device.New("d2", devAddr).Add(mustObject(t, "u", "1.001", "CR", "1/2/3"))
	if out := d2.Handle(frame(t, other, ga, apdu.GroupValueRead())); len(out) != 0 {
		t.Fatalf("answer without a value: %v", out)
	}
}

func TestIgnored(t *testing.T) {
	d := device.New("dev", devAddr)
	o := mustObject(t, "o", "1.001", "CRWU", "1/2/3")
	d.Add(o)
	_ = o.Set(true)
	// From the device itself.
	if out := d.Handle(frame(t, devAddr, ga, apdu.GroupValueRead())); out != nil {
		t.Fatal("answered its own read")
	}
	// To an individual address.
	ind := cemi.NewIndividualFrame(cemi.LDataInd, other, devAddr, knx.PriorityLow, apdu.GroupValueRead())
	if out := d.Handle(ind); out != nil {
		t.Fatal("answered an individual frame")
	}
	// Not a group value service.
	if out := d.Handle(frame(t, other, ga, []byte{0x03, 0x00})); out != nil {
		t.Fatal("answered a non group value service")
	}
	// Without C nothing happens.
	noC := mustObject(t, "noC", "1.001", "RWU", "1/2/3")
	d2 := device.New("d2", devAddr).Add(noC)
	_ = noC.Set(false)
	if out := d2.Handle(frame(t, other, ga, apdu.GroupValueRead())); out != nil {
		t.Fatal("object without C answered")
	}
	d2.Handle(frame(t, other, ga, write(t, apdu.GroupValue{Data: []byte{1}, Small: true})))
	if v, _, _ := noC.Value(); v != false {
		t.Fatal("object without C written")
	}
}

func TestWriteAndResponse(t *testing.T) {
	d := device.New("dev", devAddr)
	w := mustObject(t, "w", "1.001", "CW", "1/2/3")
	u := mustObject(t, "u", "1.001", "CU", "1/2/3")
	ro := mustObject(t, "ro", "1.001", "CR", "1/2/3")
	big := mustObject(t, "big", "9.001", "CWU", "1/2/3")
	d.Add(w, u, ro, big)
	var mu sync.Mutex
	var events []device.Event
	d.OnChange(func(e device.Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	})

	// A small write: w (W flag) takes it; u (U only) and ro do not; big
	// (2 octets) ignores the size mismatch.
	d.Handle(frame(t, other, ga, write(t, apdu.GroupValue{Data: []byte{1}, Small: true})))
	if v, ok, _ := w.Value(); !ok || v != true {
		t.Fatalf("w %v %v", v, ok)
	}
	for _, o := range []*device.GroupObject{u, ro, big} {
		if _, ok := o.Raw(); ok {
			t.Fatalf("%s written", o.Name)
		}
	}
	// A small response: u takes it, w does not change.
	d.Handle(frame(t, other, ga, response(t, apdu.GroupValue{Data: []byte{0}, Small: true})))
	if v, ok, _ := u.Value(); !ok || v != false {
		t.Fatalf("u %v %v", v, ok)
	}
	if v, _, _ := w.Value(); v != true {
		t.Fatal("w took a response")
	}
	// A 2-octet write reaches big only.
	raw, _ := big.Type.Encode(21.5)
	d.Handle(frame(t, other, ga, write(t, apdu.GroupValue{Data: raw})))
	if v, ok, _ := big.Value(); !ok || v != 21.5 {
		t.Fatalf("big %v %v", v, ok)
	}
	// A wrong-size non-small value for big is rejected by SetRaw.
	d.Handle(frame(t, other, ga, write(t, apdu.GroupValue{Data: []byte{1, 2, 3}})))
	if v, _, _ := big.Value(); v != 21.5 {
		t.Fatalf("big after bad size %v", v)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 3 {
		t.Fatalf("%d events: %+v", len(events), events)
	}
	e := events[0]
	if e.Object != w || e.Service != apdu.GroupValueWriteService || e.Source != other || e.Group != ga || e.Value != true || !bytes.Equal(e.Raw, []byte{1}) {
		t.Fatalf("event %+v", e)
	}
	if events[1].Object != u || events[1].Service != apdu.GroupValueResponseService {
		t.Fatalf("event %+v", events[1])
	}
	if events[2].Object != big || events[2].Value != 21.5 {
		t.Fatalf("event %+v", events[2])
	}
}

func TestTransmit(t *testing.T) {
	d := device.New("dev", devAddr)
	ct := mustObject(t, "ct", "9.001", "CT", "1/2/3", "1/2/4")
	noT := mustObject(t, "noT", "9.001", "CR", "1/2/3")
	noC := mustObject(t, "noC", "9.001", "T", "1/2/3")
	small := mustObject(t, "small", "1.001", "CT", "1/2/5")
	f, err := d.Transmit(ct, 19.5)
	if err != nil || f == nil {
		t.Fatalf("Transmit: %v %v", f, err)
	}
	g, _ := f.Group()
	if f.Source != devAddr || g != ga || f.MsgCode != cemi.LDataInd {
		t.Fatalf("frame %v", f)
	}
	svc, v, _ := apdu.ParseGroupValue(f.TPDU)
	if got, _ := ct.Type.Decode(v.Data); svc != apdu.GroupValueWriteService || got != 19.5 {
		t.Fatalf("frame value %v %v", svc, got)
	}
	for _, o := range []*device.GroupObject{noT, noC} {
		f, err := d.Transmit(o, 1.0)
		if err != nil || f != nil {
			t.Fatalf("%s: %v %v", o.Name, f, err)
		}
		if v, _, _ := o.Value(); v != 1.0 {
			t.Fatalf("%s value not set: %v", o.Name, v)
		}
	}
	if _, err := d.Transmit(ct, "x"); err == nil {
		t.Fatal("Transmit of a bad value")
	}
	f, err = d.Transmit(small, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, v, _ := apdu.ParseGroupValue(f.TPDU); !v.Small || v.Data[0] != 1 {
		t.Fatalf("small value %+v", v)
	}
}

func TestConcurrentHandle(t *testing.T) {
	d := device.New("dev", devAddr)
	o := mustObject(t, "o", "5.001", "CRW", "1/2/3")
	d.Add(o)
	d.OnChange(func(device.Event) {})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				d.Handle(frame(t, other, ga, write(t, apdu.GroupValue{Data: []byte{byte(j)}})))
				d.Handle(frame(t, other, ga, apdu.GroupValueRead()))
				_, _ = d.Transmit(o, float64(j%100))
				d.Objects()
			}
		}(i)
	}
	wg.Wait()
}
