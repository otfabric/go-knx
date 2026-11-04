// SPDX-License-Identifier: MIT

package tunnel_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/tunnel"
)

// fuzzPeer is a fake server that accepts every CONNECT_REQUEST on channel
// 7 and acknowledges every TUNNELLING_REQUEST.
func fuzzPeer(t testing.TB) *fakeknx.Peer {
	p := fakeknx.Listen(t)
	p.Handle(fakeknx.AnswerDisconnect)
	p.Handle(fakeknx.AnswerConnectionState)
	p.Handle(func(p *fakeknx.Peer, d fakeknx.Datagram) bool {
		switch m := d.Msg.(type) {
		case *knxnetip.ConnectRequest:
			p.Send(d.From, &knxnetip.ConnectResponse{Channel: 7, Data: p.HPAI(),
				CRD: knxnetip.CRD{Type: knxnetip.TunnelConnection, Address: tunnelAddr}})
			return true
		case *knxnetip.TunnellingRequest:
			p.Send(d.From, &knxnetip.TunnellingAck{Channel: m.Channel, Seq: m.Seq})
			return true
		}
		return false
	})
	return p
}

// FuzzReceive sends arbitrary datagrams from the server's endpoint to a
// connected tunnelling client and checks after each that the client did
// not panic and either still sends (its request is acknowledged) or has
// lost the connection, which only a frame of the server may cause; a Send
// that fails on a connection that stays connected is a defect.
func FuzzReceive(f *testing.F) {
	ld := cemi.NewGroupFrame(cemi.LDataInd, knx.MustParseIndividualAddress("1.1.1"), group, knx.PriorityLow, []byte{0x00, 0x81})
	ldb, _ := cemi.Marshal(ld)
	for _, m := range []knxnetip.Message{
		&knxnetip.TunnellingRequest{Channel: 7, Seq: 0, CEMI: ldb},
		&knxnetip.TunnellingRequest{Channel: 7, Seq: 200, CEMI: ldb},
		&knxnetip.TunnellingRequest{Channel: 8, Seq: 0, CEMI: ldb},
		&knxnetip.TunnellingAck{Channel: 7, Seq: 0},
		&knxnetip.TunnellingAck{Channel: 7, Seq: 0, Status: knxnetip.StatusConnectionID},
		&knxnetip.ConnectResponse{Channel: 9, Status: knxnetip.StatusNoMoreConnections},
		&knxnetip.ConnectionStateResponse{Channel: 7, Status: knxnetip.StatusConnectionID},
		&knxnetip.DisconnectRequest{Channel: 8, Control: knxnetip.RouteBackHPAI()},
		&knxnetip.DisconnectResponse{Channel: 7},
		&knxnetip.TunnellingFeature{Type: knxnetip.TunnellingFeatureInfoType, Channel: 7, Seq: 0, Feature: knxnetip.FeatureBusConnectionStatus, Value: []byte{1}},
	} {
		b, err := knxnetip.Marshal(m)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte{0x06, 0x10, 0x04, 0x20, 0x00, 0x0a, 0x04, 0x07, 0x00, 0x00})
	f.Add([]byte{0x06, 0x10, 0x04, 0x20, 0xff, 0xff})

	p := fuzzPeer(f)
	var c *tunnel.Conn
	f.Cleanup(func() {
		if c != nil {
			_ = c.Close()
		}
	})
	dial := func(t *testing.T) {
		if c != nil {
			_ = c.Close()
		}
		var err error
		cx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err = tunnel.Dial(cx, p.String(), tunnel.WithConfirm(false, 0), tunnel.WithRequestTimeout(200*time.Millisecond),
			tunnel.WithConnectTimeout(time.Second), tunnel.WithQueueSize(4))
		if err != nil {
			t.Fatal(err)
		}
	}
	w := cemi.NewGroupFrame(cemi.LDataReq, 0, group, knx.PriorityLow, []byte{0x00, 0x80})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 2048 {
			return
		}
		// The client answers a DISCONNECT_REQUEST at the control endpoint
		// it names: no datagrams to hosts outside the loopback interface.
		if m, err := knxnetip.Parse(b); err == nil {
			if d, ok := m.(*knxnetip.DisconnectRequest); ok {
				if a := d.Control.Addr.Addr(); a.IsValid() && !a.IsLoopback() && !a.IsUnspecified() {
					return
				}
			}
		}
		if c == nil || c.State() != knx.StateConnected {
			dial(t)
		}
		p.SendRaw(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(c.LocalAddr().(*net.UDPAddr).Port)), b)
		cx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		err := c.Send(cx, w)
		if err != nil {
			// A connection lost while Send wrote (the socket closed under
			// it) reports knx.ErrConnectionLost or knx.ErrClosed too.
			if !errors.Is(err, knx.ErrConnectionLost) && !errors.Is(err, knx.ErrClosed) {
				if _, ok := errors.AsType[*knxnetip.StatusError](err); !ok {
					t.Fatalf("send after % X: %v", b, err)
				}
				return // a spoofed negative ACK of the server
			}
			deadline := time.Now().Add(2 * time.Second)
			for c.State() == knx.StateConnected {
				if time.Now().After(deadline) {
					t.Fatalf("send failed (%v) on a connection that stays connected, after % X", err, b)
				}
				time.Sleep(time.Millisecond)
			}
		}
		for {
			rc, cancel := context.WithTimeout(context.Background(), 0)
			_, err := c.Receive(rc)
			cancel()
			if err != nil {
				break
			}
		}
	})
}
