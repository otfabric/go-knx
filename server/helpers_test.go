// SPDX-License-Identifier: MIT

package server_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/server"
	"github.com/otfabric/go-knx/tunnel"
)

const wait = 2 * time.Second

var (
	serverAddr = knx.MustParseIndividualAddress("15.15.0")
	slot1      = knx.MustParseIndividualAddress("1.1.10")
	slot2      = knx.MustParseIndividualAddress("1.1.11")
	ga         = knx.MustParseGroupAddress("1/2/3")
)

type metrics struct {
	knx.NopMetrics
	mu          sync.Mutex
	retransmits int
	dropped     map[string]int
	decode      int
	disconnects []error
	sent        map[uint16]int
}

func newMetrics() *metrics { return &metrics{dropped: map[string]int{}, sent: map[uint16]int{}} }

func (m *metrics) OnRetransmit(net.Addr, uint8) { m.mu.Lock(); m.retransmits++; m.mu.Unlock() }
func (m *metrics) OnDropped(_ net.Addr, r string) {
	m.mu.Lock()
	m.dropped[r]++
	m.mu.Unlock()
}
func (m *metrics) OnDecodeError(net.Addr, error) { m.mu.Lock(); m.decode++; m.mu.Unlock() }
func (m *metrics) OnDisconnect(_ net.Addr, _ uint8, err error) {
	m.mu.Lock()
	m.disconnects = append(m.disconnects, err)
	m.mu.Unlock()
}
func (m *metrics) OnFrameSent(_ net.Addr, svc uint16, _ int) {
	m.mu.Lock()
	m.sent[svc]++
	m.mu.Unlock()
}

func (m *metrics) get(f func(m *metrics) int) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return f(m)
}

func eventually(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(wait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func ctx(t testing.TB) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

func start(t testing.TB, opts ...server.Option) (*server.Server, *metrics) {
	t.Helper()
	m := newMetrics()
	opts = append([]server.Option{server.WithListenAddr("127.0.0.1:0"), server.WithDiscovery(false),
		server.WithTunnelAddresses(slot1, slot2), server.WithMetrics(m)}, opts...)
	s, err := server.New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, m
}

// addrOf returns the endpoint to reach s at (127.0.0.1 for a wildcard
// listener).
func addrOf(s *server.Server) netip.AddrPort {
	a := s.Addr()
	if a.Addr().IsUnspecified() {
		return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), a.Port())
	}
	return a
}

// dialTunnel connects a tunnelling client to s.
func dialTunnel(t testing.TB, s *server.Server, opts ...tunnel.Option) *tunnel.Conn {
	t.Helper()
	c, err := tunnel.Dial(ctx(t), addrOf(s).String(), append([]tunnel.Option{tunnel.WithConfirm(true, wait)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// raw is a hand-driven tunnelling client.
type raw struct {
	t    testing.TB
	p    *fakeknx.Peer
	srv  netip.AddrPort
	data netip.AddrPort // the server's data endpoint
	ch   uint8
	addr knx.IndividualAddress
}

func newRaw(t testing.TB, s *server.Server) *raw {
	return &raw{t: t, p: fakeknx.Listen(t), srv: addrOf(s)}
}

func (r *raw) connect(cri knxnetip.CRI) *knxnetip.ConnectResponse {
	r.t.Helper()
	r.p.Send(r.srv, &knxnetip.ConnectRequest{Control: r.p.HPAI(), Data: r.p.HPAI(), CRI: cri})
	resp, _ := fakeknx.Expect[*knxnetip.ConnectResponse](r.p, wait)
	if resp.Status == knxnetip.StatusNoError {
		r.ch, r.addr, r.data = resp.Channel, resp.CRD.Address, resp.Data.Addr
	}
	return resp
}

func dialRaw(t testing.TB, s *server.Server) *raw {
	t.Helper()
	r := newRaw(t, s)
	if resp := r.connect(knxnetip.TunnelCRI(knxnetip.TunnelLinkLayer)); resp.Status != knxnetip.StatusNoError {
		t.Fatalf("connect: %s", resp.Status)
	}
	return r
}

// request sends a TUNNELLING_REQUEST with sequence seq.
func (r *raw) request(seq uint8, f cemi.Frame) {
	r.t.Helper()
	b, err := cemi.Marshal(f)
	if err != nil {
		r.t.Fatal(err)
	}
	r.p.Send(r.data, &knxnetip.TunnellingRequest{Channel: r.ch, Seq: seq, CEMI: b})
}

// nextFrame returns the next TUNNELLING_REQUEST from the server and
// acknowledges it.
func (r *raw) nextFrame() *cemi.LData {
	r.t.Helper()
	req, d := fakeknx.Expect[*knxnetip.TunnellingRequest](r.p, wait)
	if req.Channel != r.ch {
		r.t.Fatalf("request on channel %d, want %d", req.Channel, r.ch)
	}
	r.p.Send(d.From, &knxnetip.TunnellingAck{Channel: r.ch, Seq: req.Seq})
	f, err := cemi.Parse(req.CEMI)
	if err != nil {
		r.t.Fatal(err)
	}
	return f.(*cemi.LData)
}

func write(g knx.GroupAddress, v byte) *cemi.LData {
	tpdu, err := apdu.GroupValueWrite(apdu.GroupValue{Data: []byte{v}})
	if err != nil {
		panic(err)
	}
	return cemi.NewGroupFrame(cemi.LDataReq, 0, g, knx.PriorityLow, tpdu)
}

func receive(t testing.TB, c *tunnel.Conn) *cemi.LData {
	t.Helper()
	cx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	f, err := c.Receive(cx)
	if err != nil {
		t.Fatal(err)
	}
	ld, ok := f.(*cemi.LData)
	if !ok {
		t.Fatalf("frame %v", f)
	}
	return ld
}

func noFrame(t testing.TB, c *tunnel.Conn) {
	t.Helper()
	cx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if f, err := c.Receive(cx); err == nil {
		t.Fatalf("unexpected frame %v", f)
	}
}

func lastOctet(f *cemi.LData) byte { return f.TPDU[len(f.TPDU)-1] }

func addrs(n int) []knx.IndividualAddress {
	out := make([]knx.IndividualAddress, n)
	for i := range out {
		out[i] = knx.MustParseIndividualAddress(fmt.Sprintf("1.2.%d", i+1))
	}
	return out
}
