// SPDX-License-Identifier: MIT

package devmgmt_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/devmgmt"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/server"
)

// A server that acknowledges the request and never confirms it: without
// a deadline on the context, PropRead ends after DefaultTimeout with
// knx.ErrTimeout instead of blocking for ever.
func TestPropReadDefaultTimeout(t *testing.T) {
	p := fakeknx.Listen(t)
	p.Handle(func(p *fakeknx.Peer, d fakeknx.Datagram) bool {
		switch m := d.Msg.(type) {
		case *knxnetip.ConnectRequest:
			p.Send(m.Control.Addr, &knxnetip.ConnectResponse{Channel: 3, Data: p.HPAI(), CRD: knxnetip.CRD{Type: knxnetip.DeviceManagementConnection}})
		case *knxnetip.DeviceConfigurationRequest:
			p.Send(d.From, &knxnetip.DeviceConfigurationAck{Channel: m.Channel, Seq: m.Seq})
		default:
			return fakeknx.AnswerConnectionState(p, d) || fakeknx.AnswerDisconnect(p, d)
		}
		return true
	})
	dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := devmgmt.Dial(dctx, p.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	_, err = c.PropRead(context.Background(), devmgmt.ObjectDevice, 1, devmgmt.PIDSerialNumber, 1, 1)
	if !errors.Is(err, knx.ErrTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v", err)
	}
	if d := time.Since(start); d < devmgmt.DefaultTimeout-100*time.Millisecond || d > devmgmt.DefaultTimeout+2*time.Second {
		t.Fatalf("took %v, want about %v", d, devmgmt.DefaultTimeout)
	}
}

// A write too long for one KNXnet/IP frame is refused with
// knx.ErrInvalidValue, and the connection stays usable.
func TestPropWriteTooLongKeepsConnection(t *testing.T) {
	s, err := server.New(server.WithListenAddr("127.0.0.1:0"), server.WithDiscovery(false), server.WithName("before"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := devmgmt.Dial(ctx, s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	err = c.PropWrite(ctx, devmgmt.ObjectKNXnetIPParameter, 1, devmgmt.PIDFriendlyName, 1, 1, make([]byte, 2000))
	if !errors.Is(err, knx.ErrInvalidValue) || errors.Is(err, knx.ErrConnectionLost) {
		t.Fatalf("oversized write: %v", err)
	}
	if b, err := c.PropRead(ctx, devmgmt.ObjectKNXnetIPParameter, 1, devmgmt.PIDFriendlyName, 1, 6); err != nil || string(b) != "before" {
		t.Fatalf("read after the refused write: %q %v", b, err)
	}
}
