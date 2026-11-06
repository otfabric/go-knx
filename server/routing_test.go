// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/routing"
	"github.com/otfabric/go-knx/server"
)

// startRouter starts a routing server on a test group. Its socket is
// bound to the group's port on every address, so the tests can inject
// routing indications by unicast without multicast support.
func startRouter(t *testing.T, opts ...server.Option) (*server.Server, *metrics, netip.AddrPort, netip.AddrPort) {
	t.Helper()
	g := fakeknx.Group(t)
	if lo := fakeknx.MulticastInterface(); lo != "" {
		opts = append([]server.Option{server.WithInterface(lo)}, opts...)
	}
	s, m := start(t, append([]server.Option{server.WithListenAddr(fmt.Sprintf(":%d", g.Port())),
		server.WithMulticastGroup(g.String()), server.WithRouting(true), server.WithDiscovery(false)}, opts...)...)
	return s, m, g, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), g.Port())
}

func indication(v byte, hops uint8) []byte {
	tpdu, _ := apdu.GroupValueWrite(apdu.GroupValue{Data: []byte{v}})
	f := cemi.NewGroupFrame(cemi.LDataInd, knx.MustParseIndividualAddress("2.2.2"), ga, knx.PriorityLow, tpdu)
	f.SetHopCount(hops)
	b, _ := cemi.Marshal(f)
	return b
}

func TestRoutingInbound(t *testing.T) {
	leak.Check(t)
	s, m, g, local := startRouter(t)
	c := dialTunnel(t, s)
	origins := make(chan server.Origin, 8)
	defer s.Subscribe(func(tg server.Telegram) { origins <- tg.Origin })()
	p := fakeknx.Listen(t)

	p.Send(local, &knxnetip.RoutingIndication{CEMI: indication(1, 6)})
	if f := receive(t, c); f.Source != knx.MustParseIndividualAddress("2.2.2") || lastOctet(f) != 1 {
		t.Fatalf("routed telegram %v", f)
	}
	if o := <-origins; o != server.FromRouting {
		t.Fatalf("origin %v", o)
	}
	// System broadcasts, non-L_Data.ind frames, undecodable cEMI, busy
	// and lost message notifications are not delivered.
	p.Send(local, &knxnetip.RoutingIndication{SystemBroadcast: true, CEMI: indication(2, 6)})
	req := indication(3, 6)
	req[0] = byte(cemi.LDataReq)
	p.Send(local, &knxnetip.RoutingIndication{CEMI: req})
	p.Send(local, &knxnetip.RoutingIndication{CEMI: []byte{0x29, 0x00}})
	p.Send(local, &knxnetip.RoutingBusy{WaitTime: 10})
	p.Send(local, &knxnetip.RoutingLostMessage{Lost: 1})
	p.Send(local, &knxnetip.TunnellingAck{Channel: 99})
	eventually(t, "decode error", func() bool { return m.get(func(m *metrics) int { return m.decode }) == 1 })
	p.Send(local, &knxnetip.RoutingIndication{CEMI: indication(4, 6)})
	if f := receive(t, c); lastOctet(f) != 4 {
		t.Fatalf("got %v, want the fourth telegram only", f)
	}
	// Routed telegrams are not sent back to the group.
	if n := m.get(func(m *metrics) int { return m.sent[uint16(knxnetip.RoutingIndicationType)] }); n != 0 {
		t.Fatalf("%d indications sent to %s", n, g)
	}

	// Description announces routing and the group.
	p.Send(local, &knxnetip.DescriptionRequest{Control: p.HPAI()})
	dr, _ := fakeknx.Expect[*knxnetip.DescriptionResponse](p, wait)
	d, _ := dr.DIBs.DeviceInfo()
	fam, _ := dr.DIBs.SupportedServices()
	if v, ok := fam.Version(knxnetip.FamilyRouting); !ok || v != 1 || d.Multicast != g.Addr() {
		t.Fatalf("description %+v %+v", d, fam)
	}
}

func TestRoutingOutbound(t *testing.T) {
	leak.Check(t)
	s, m, _, _ := startRouter(t, server.WithRoutingRate(10), server.WithMulticastTTL(1), server.WithQueueSize(2))
	sent := func() int {
		return m.get(func(m *metrics) int { return m.sent[uint16(knxnetip.RoutingIndicationType)] })
	}
	dropped := func() int { return m.get(func(m *metrics) int { return m.dropped["routing_rate"] }) }
	c := dialTunnel(t, s)
	if err := c.Send(ctx(t), write(ga, 1)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "routing indication", func() bool { return sent() == 1 })
	// Hop count 0 is not routed.
	f := write(ga, 2)
	f.SetHopCount(0)
	if err := s.Send(f); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if sent() != 1 {
		t.Fatal("hop count 0 routed")
	}
	// At 10/s indications are 100 ms apart: a burst is queued, not sent
	// back to back, and what does not fit in the queue (2, plus the one
	// the sender holds, plus at most one sent at once) is dropped and
	// counted.
	start := time.Now()
	for v := range 6 {
		_ = s.GroupWrite(ga, apdu.GroupValue{Data: []byte{byte(v)}})
	}
	if d := dropped(); d < 2 {
		t.Fatalf("dropped %d of a burst of 6 with a queue of 2", d)
	}
	eventually(t, "queued indications", func() bool { return sent()+dropped() == 7 })
	if d := time.Since(start); d < 150*time.Millisecond {
		t.Fatalf("%d queued indications sent within %v at 10/s", sent()-1, d)
	}
}

// TestRoutingBusyPausesServer: a peer's ROUTING_BUSY holds the server's
// own routing indications for the wait time; they are queued, not
// dropped.
func TestRoutingBusyPausesServer(t *testing.T) {
	leak.Check(t)
	s, m, _, local := startRouter(t, server.WithRoutingRate(0))
	sent := func() int {
		return m.get(func(m *metrics) int { return m.sent[uint16(knxnetip.RoutingIndicationType)] })
	}
	p := fakeknx.Listen(t)
	p.Send(local, &knxnetip.RoutingBusy{WaitTime: 300})
	// The busy frame is handled by the reader; a description request
	// behind it tells when it has been.
	p.Send(local, &knxnetip.DescriptionRequest{Control: p.HPAI()})
	fakeknx.Expect[*knxnetip.DescriptionResponse](p, wait)
	start := time.Now()
	for v := range 3 {
		if err := s.GroupWrite(ga, apdu.GroupValue{Data: []byte{byte(v)}}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(150 * time.Millisecond)
	if n := sent(); n != 0 {
		t.Fatalf("%d indications sent during ROUTING_BUSY", n)
	}
	eventually(t, "indications after the pause", func() bool { return sent() == 3 })
	if d := time.Since(start); d < 250*time.Millisecond {
		t.Fatalf("indications sent %v after ROUTING_BUSY with a wait of 300 ms", d)
	}
	if n := m.get(func(m *metrics) int { return m.dropped["routing_rate"] }); n != 0 {
		t.Fatalf("%d indications dropped", n)
	}
	// Close ends a sender that waits for a pause.
	p.Send(local, &knxnetip.RoutingBusy{WaitTime: 60000})
	p.Send(local, &knxnetip.DescriptionRequest{Control: p.HPAI()})
	fakeknx.Expect[*knxnetip.DescriptionResponse](p, wait)
	_ = s.GroupWrite(ga, apdu.GroupValue{Data: []byte{9}})
	done := make(chan struct{})
	go func() { s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(wait):
		t.Fatal("Close blocked by a paused routing sender")
	}
}

// TestRoutingMulticast needs real multicast: a routing.Conn on the same
// host sends an indication to the group and the server delivers it.
func TestRoutingMulticast(t *testing.T) {
	fakeknx.RequireMulticast(t)
	leak.Check(t)
	s, _, g, _ := startRouter(t)
	c := dialTunnel(t, s)
	ropts := []routing.Option{routing.WithGroup(g.String()), routing.WithLoopback(true)}
	if lo := fakeknx.MulticastInterface(); lo != "" {
		ropts = append(ropts, routing.WithInterface(lo))
	}
	r, err := routing.Listen(ctx(t), ropts...)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	f, _ := cemi.Parse(indication(5, 6))
	if err := r.Send(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if got := receive(t, c); lastOctet(got) != 5 {
		t.Fatalf("got %v", got)
	}
}
