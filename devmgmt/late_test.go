// SPDX-License-Identifier: MIT

package devmgmt_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/devmgmt"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/knxnetip"
)

// wait bounds a wait that would otherwise hang.
const wait = 2 * time.Second

// A confirmation that arrives after its request timed out, and before the
// next request of the same property is sent, is discarded: the next
// PropRead returns the answer to its own request. (One that arrives after
// the next request was sent is still taken for its answer: cEMI device
// management carries no correlation.)
func TestLateConfirmationDiscarded(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	p.Handle(func(p *fakeknx.Peer, d fakeknx.Datagram) bool {
		switch m := d.Msg.(type) {
		case *knxnetip.ConnectRequest:
			p.Send(m.Control.Addr, &knxnetip.ConnectResponse{Channel: 3, Data: p.HPAI(), CRD: knxnetip.CRD{Type: knxnetip.DeviceManagementConnection}})
			return true
		case *knxnetip.DeviceConfigurationRequest:
			// Acknowledged here, answered by the test.
			p.Send(d.From, &knxnetip.DeviceConfigurationAck{Channel: m.Channel, Seq: m.Seq})
			return false
		}
		return fakeknx.AnswerConnectionState(p, d) || fakeknx.AnswerDisconnect(p, d)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := devmgmt.Dial(ctx, p.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	read := func(ctx context.Context) <-chan []byte {
		ch := make(chan []byte, 1)
		go func() {
			b, err := c.PropRead(ctx, devmgmt.ObjectDevice, 1, devmgmt.PIDSerialNumber, 1, 1)
			if err != nil {
				t.Errorf("PropRead: %v", err)
			}
			ch <- b
		}()
		return ch
	}
	// The answer of the server to the request in d, with value v.
	answer := func(d fakeknx.Datagram, seq uint8, v []byte) {
		f, err := cemi.Parse(d.Msg.(*knxnetip.DeviceConfigurationRequest).CEMI)
		if err != nil {
			t.Fatal(err)
		}
		con := *f.(*cemi.Property)
		con.MsgCode, con.Data = cemi.MPropReadCon, v
		b, err := cemi.Marshal(&con)
		if err != nil {
			t.Fatal(err)
		}
		p.Send(d.From, &knxnetip.DeviceConfigurationRequest{Channel: 3, Seq: seq, CEMI: b})
	}
	stale, current := []byte{0, 0xFA, 0, 0, 0, 1}, []byte{0, 0xFA, 0, 0, 0, 2}

	// The first read is acknowledged and not confirmed before its deadline.
	rctx, rcancel := context.WithTimeout(ctx, 50*time.Millisecond)
	_, err = c.PropRead(rctx, devmgmt.ObjectDevice, 1, devmgmt.PIDSerialNumber, 1, 1)
	rcancel()
	if !errors.Is(err, knx.ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first PropRead = %v, want knx.ErrTimeout", err)
	}
	_, first := fakeknx.Expect[*knxnetip.DeviceConfigurationRequest](p, wait)
	// Its confirmation comes late, followed by an M_Reset.ind. Once the
	// client acknowledged the second frame, its reader has queued both.
	answer(first, 0, stale)
	reset, err := cemi.Marshal(&cemi.Reset{MsgCode: cemi.MResetInd})
	if err != nil {
		t.Fatal(err)
	}
	p.Send(first.From, &knxnetip.DeviceConfigurationRequest{Channel: 3, Seq: 1, CEMI: reset})
	for {
		ack, _ := fakeknx.Expect[*knxnetip.DeviceConfigurationAck](p, wait)
		if ack.Seq == 1 {
			break
		}
	}

	// The next read of the same property gets the answer to its own
	// request.
	got := read(ctx)
	_, second := fakeknx.Expect[*knxnetip.DeviceConfigurationRequest](p, wait)
	answer(second, 2, current)
	select {
	case b := <-got:
		if !bytes.Equal(b, current) {
			t.Fatalf("PropRead after a late confirmation = % X, want % X (the answer to its own request)", b, current)
		}
	case <-time.After(wait):
		t.Fatal("timed out waiting for the second PropRead")
	}
}
