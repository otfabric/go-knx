// SPDX-License-Identifier: MIT

package server_test

import (
	"bytes"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/device"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/server"
)

// Close contract 3: Send, GroupWrite and Transmit after Close return
// knx.ErrClosed and have no effect: no tap runs, no device sees the
// telegram, and Transmit leaves the group object as it was.
func TestOperationsAfterClose(t *testing.T) {
	leak.Check(t)
	s, _ := start(t)
	sender := device.New("sender", knx.MustParseIndividualAddress("1.1.20"))
	out, err := device.NewGroupObject("out", "1.001", "CT", "1/2/7")
	if err != nil {
		t.Fatal(err)
	}
	sender.Add(out)
	receiver := device.New("receiver", knx.MustParseIndividualAddress("1.1.21"))
	in, err := device.NewGroupObject("in", "1.001", "CW", "1/2/7", ga.String())
	if err != nil {
		t.Fatal(err)
	}
	receiver.Add(in)
	s.AddDevice(sender)
	s.AddDevice(receiver)
	var taps atomic.Int32
	s.Subscribe(func(server.Telegram) { taps.Add(1) })
	// Before Close the calls reach the network.
	if err := s.Transmit(sender, out, false); err != nil {
		t.Fatal(err)
	}
	if raw, _ := in.Raw(); taps.Load() != 1 || !bytes.Equal(raw, []byte{0}) {
		t.Fatalf("%d tap calls and the receiving object at % X after a Transmit before Close, want 1 and 00", taps.Load(), raw)
	}
	on, err := apdu.GroupValueWrite(apdu.GroupValue{Data: []byte{1}, Small: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	taps.Store(0)
	for name, call := range map[string]func() error{
		"Send":       func() error { return s.Send(cemi.NewGroupFrame(cemi.LDataInd, 0, ga, knx.PriorityLow, on)) },
		"GroupWrite": func() error { return s.GroupWrite(ga, apdu.GroupValue{Data: []byte{1}, Small: true}) },
		"Transmit":   func() error { return s.Transmit(sender, out, true) },
	} {
		if err := call(); !errors.Is(err, knx.ErrClosed) {
			t.Errorf("%s after Close = %v, want knx.ErrClosed", name, err)
		}
	}
	if n := taps.Load(); n != 0 {
		t.Errorf("%d tap calls after Close, want 0", n)
	}
	if v, _, _ := out.Value(); v != false {
		t.Errorf("Transmit after Close set the group object to %v, want false", v)
	}
	if raw, _ := in.Raw(); !bytes.Equal(raw, []byte{0}) {
		t.Errorf("the receiving object is at % X after the calls after Close, want 00: a device received a telegram", raw)
	}
}
