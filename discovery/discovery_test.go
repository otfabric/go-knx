// SPDX-License-Identifier: MIT

package discovery_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/discovery"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/server"
)

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

func startServer(t *testing.T, opts ...server.Option) *server.Server {
	t.Helper()
	s, err := server.New(append([]server.Option{server.WithListenAddr("127.0.0.1:0"), server.WithDiscovery(false)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func deviceInfo(name string) knxnetip.DIBs {
	return knxnetip.DIBs{
		knxnetip.DeviceInfo{Medium: knxnetip.MediumIP, Name: name, Multicast: netip.IPv4Unspecified(), Serial: [6]byte{0, 1, 0, 0, 0, 1}},
		knxnetip.ServiceFamilies{Families: []knxnetip.ServiceFamily{{ID: knxnetip.FamilyCore, Version: 2}}},
	}
}

// counting answers requests of type T from the n-th one on (1-based; 0:
// never) with reply, and counts them.
type counting struct {
	mu sync.Mutex
	n  int
}

func (c *counting) get() int { c.mu.Lock(); defer c.mu.Unlock(); return c.n }

func answer[T knxnetip.Message](p *fakeknx.Peer, from int, reply func(d fakeknx.Datagram) knxnetip.Message) *counting {
	c := &counting{}
	p.Handle(func(p *fakeknx.Peer, d fakeknx.Datagram) bool {
		if _, ok := d.Msg.(T); !ok {
			return false
		}
		c.mu.Lock()
		c.n++
		n := c.n
		c.mu.Unlock()
		if from > 0 && n >= from {
			to := d.From
			switch m := d.Msg.(type) {
			case *knxnetip.DescriptionRequest:
				if !m.Control.IsRouteBack() {
					to = m.Control.Addr
				}
			case *knxnetip.SearchRequest:
				if !m.Discovery.IsRouteBack() {
					to = m.Discovery.Addr
				}
			case *knxnetip.SearchRequestExt:
				if !m.Discovery.IsRouteBack() {
					to = m.Discovery.Addr
				}
			}
			p.Send(to, reply(d))
		}
		return true
	})
	return c
}

func TestDescribe(t *testing.T) {
	leak.Check(t)
	s := startServer(t, server.WithName("describe me"))
	dibs, err := discovery.Describe(ctx(t), s.Addr().String(), discovery.WithTimeout(time.Second), discovery.WithLogger(nil))
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := dibs.DeviceInfo(); !ok || d.Name != "describe me" {
		t.Fatalf("DIBs %+v", dibs)
	}
}

func TestDescribeRetries(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	n := answer[*knxnetip.DescriptionRequest](p, 3, func(fakeknx.Datagram) knxnetip.Message {
		return &knxnetip.DescriptionResponse{DIBs: deviceInfo("third time")}
	})
	dibs, err := discovery.Describe(ctx(t), p.String(), discovery.WithTimeout(300*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := dibs.DeviceInfo(); d.Name != "third time" || n.get() != 3 {
		t.Fatalf("name %q after %d requests", d.Name, n.get())
	}
}

func TestDescribeTimeout(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	n := answer[*knxnetip.DescriptionRequest](p, 0, nil)
	start := time.Now()
	_, err := discovery.Describe(ctx(t), p.String(), discovery.WithTimeout(150*time.Millisecond))
	if !errors.Is(err, knx.ErrTimeout) {
		t.Fatalf("err %v", err)
	}
	if n.get() != 3 {
		t.Fatalf("%d requests, want 3", n.get())
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("took %v", d)
	}
}

func TestDescribeIgnoresOtherMessages(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	answer[*knxnetip.DescriptionRequest](p, 1, func(d fakeknx.Datagram) knxnetip.Message {
		// Another message first, then the answer.
		p.Send(d.From, &knxnetip.SearchResponse{Control: p.HPAI(), DIBs: deviceInfo("search")})
		return &knxnetip.DescriptionResponse{DIBs: deviceInfo("described")}
	})
	dibs, err := discovery.Describe(ctx(t), p.String(), discovery.WithTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := dibs.DeviceInfo(); d.Name != "described" {
		t.Fatalf("name %q", d.Name)
	}
}

// A malformed datagram is skipped: the valid answer after it counts.
func TestDescribeMalformedAnswer(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	p.Handle(func(p *fakeknx.Peer, d fakeknx.Datagram) bool {
		p.SendRaw(d.From, []byte{0x06, 0x10, 0x02, 0x04, 0x00, 0x07, 0x01})
		p.Send(d.From, &knxnetip.DescriptionResponse{DIBs: deviceInfo("described")})
		return true
	})
	dibs, err := discovery.Describe(ctx(t), p.String(), discovery.WithTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := dibs.DeviceInfo(); d.Name != "described" {
		t.Fatalf("name %q", d.Name)
	}
}

func TestDescribeNATAndCancel(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	routeBack := make(chan bool, 3)
	p.Handle(func(p *fakeknx.Peer, d fakeknx.Datagram) bool {
		if m, ok := d.Msg.(*knxnetip.DescriptionRequest); ok {
			routeBack <- m.Control.IsRouteBack()
		}
		return true
	})
	c, cancel := context.WithCancel(context.Background())
	go func() {
		<-routeBack
		cancel()
	}()
	_, err := discovery.Describe(c, p.String(), discovery.WithNAT(true), discovery.WithTimeout(time.Minute))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	// The request announced 0.0.0.0:0.
	p2 := fakeknx.Listen(t)
	answer[*knxnetip.DescriptionRequest](p2, 1, func(d fakeknx.Datagram) knxnetip.Message {
		if !d.Msg.(*knxnetip.DescriptionRequest).Control.IsRouteBack() {
			t.Errorf("NAT request with HPAI %s", d.Msg.(*knxnetip.DescriptionRequest).Control)
		}
		return &knxnetip.DescriptionResponse{DIBs: deviceInfo("nat")}
	})
	if _, err := discovery.Describe(ctx(t), p2.String(), discovery.WithNAT(true), discovery.WithTimeout(time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestOptionErrors(t *testing.T) {
	leak.Check(t)
	for name, opts := range map[string][]discovery.Option{
		"timeout":   {discovery.WithTimeout(0)},
		"repeat 0":  {discovery.WithRepeat(0)},
		"repeat 4":  {discovery.WithRepeat(4)},
		"interface": {discovery.WithInterface("no-such-interface0")},
		"local":     {discovery.WithLocalAddr("127.0.0.1:x")},
	} {
		if _, err := discovery.Search(ctx(t), append(opts, discovery.WithUnicast("127.0.0.1:1"))...); !errors.Is(err, knx.ErrInvalidOption) {
			t.Errorf("Search %s: %v", name, err)
		}
		if _, err := discovery.Describe(ctx(t), "127.0.0.1:1", opts...); !errors.Is(err, knx.ErrInvalidOption) {
			t.Errorf("Describe %s: %v", name, err)
		}
	}
	if _, err := discovery.Search(ctx(t), discovery.WithNAT(true)); !errors.Is(err, knx.ErrInvalidOption) {
		t.Errorf("multicast NAT: %v", err)
	}
	if _, err := discovery.Search(ctx(t), discovery.WithUnicast("127.0.0.1:x")); !errors.Is(err, knx.ErrInvalidOption) {
		t.Errorf("bad unicast: %v", err)
	}
	if _, err := discovery.Describe(ctx(t), "[::1]:3671"); !errors.Is(err, knx.ErrInvalidOption) {
		t.Errorf("IPv6: %v", err)
	}
	if _, err := discovery.Describe(ctx(t), "127.0.0.1:1", discovery.WithLocalAddr("192.0.2.1:0")); err == nil {
		t.Error("bind to a foreign address succeeded")
	}
}

func TestDirectedSearch(t *testing.T) {
	leak.Check(t)
	s := startServer(t, server.WithName("directed"))
	addr := s.Addr().String()
	rs, err := discovery.Search(ctx(t), discovery.WithUnicast(addr), discovery.WithTimeout(200*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 || rs[0].Extended || rs[0].Endpoint() != s.Addr() || rs[0].Device().Name != "directed" {
		t.Fatalf("results %+v", rs)
	}
	if v, ok := rs[0].Services().Version(knxnetip.FamilyTunnelling); !ok || v != 1 {
		t.Fatalf("services %+v", rs[0].Services())
	}
	// Extended, with parameters.
	rs, err = discovery.Search(ctx(t), discovery.WithUnicast(addr), discovery.WithTimeout(200*time.Millisecond),
		discovery.WithExtended(knxnetip.SearchParam{Type: knxnetip.SRPRequestDIBs, Data: []byte{byte(knxnetip.DIBTunnellingInfo)}}))
	if err != nil || len(rs) != 1 || !rs[0].Extended {
		t.Fatalf("extended %+v %v", rs, err)
	}
	if _, ok := rs[0].DIBs.Find(knxnetip.DIBTunnellingInfo); !ok {
		t.Fatalf("no TUNNELLING_INFO: %+v", rs[0].DIBs)
	}
	// A search parameter the server cannot satisfy: no answer, an empty
	// (not nil) result.
	rs, err = discovery.Search(ctx(t), discovery.WithUnicast(addr), discovery.WithTimeout(100*time.Millisecond),
		discovery.WithExtended(knxnetip.SearchParam{Type: knxnetip.SRPProgrammingMode}))
	if err != nil || rs == nil || len(rs) != 0 {
		t.Fatalf("unsatisfiable: %#v %v", rs, err)
	}
	// From the loopback interface, and with NAT.
	if lo := loopbackName(t); lo != "" {
		rs, err = discovery.Search(ctx(t), discovery.WithUnicast(addr), discovery.WithInterface(lo), discovery.WithTimeout(200*time.Millisecond))
		if err != nil || len(rs) != 1 {
			t.Fatalf("from %s: %+v %v", lo, rs, err)
		}
	}
	rs, err = discovery.Search(ctx(t), discovery.WithUnicast(addr), discovery.WithNAT(true), discovery.WithTimeout(200*time.Millisecond))
	if err != nil || len(rs) != 1 {
		t.Fatalf("NAT: %+v %v", rs, err)
	}
}

func loopbackName(t *testing.T) string {
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			return i.Name
		}
	}
	return ""
}

func TestSearchRepeat(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	// The first request is lost; the second is answered after some
	// noise, with the route back HPAI.
	n := answer[*knxnetip.SearchRequest](p, 2, func(d fakeknx.Datagram) knxnetip.Message {
		p.SendRaw(d.From, []byte{1, 2, 3}) // garbage is skipped
		p.Send(d.From, &knxnetip.DescriptionResponse{DIBs: deviceInfo("other")})
		return &knxnetip.SearchResponse{Control: knxnetip.RouteBackHPAI(), DIBs: deviceInfo("second")}
	})
	start := time.Now()
	rs, err := discovery.Search(ctx(t), discovery.WithUnicast(p.String()), discovery.WithRepeat(2), discovery.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if n.get() != 2 {
		t.Fatalf("%d requests, want 2 (results %+v)", n.get(), rs)
	}
	if len(rs) != 1 || rs[0].From != p.Addr() || rs[0].Endpoint() != p.Addr() || rs[0].Device().Name != "second" {
		t.Fatalf("results %+v", rs)
	}
	// A directed search returns on its answer, not at the timeout.
	if d := time.Since(start); d > 2500*time.Millisecond {
		t.Fatalf("took %v", d)
	}
}

func TestSearchRepeatBoundedByTimeout(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	n := answer[*knxnetip.SearchRequest](p, 0, nil)
	rs, err := discovery.Search(ctx(t), discovery.WithUnicast(p.String()), discovery.WithRepeat(3), discovery.WithTimeout(200*time.Millisecond))
	if err != nil || len(rs) != 0 {
		t.Fatalf("%+v %v", rs, err)
	}
	if n.get() != 1 {
		t.Fatalf("%d requests within 200 ms, want 1", n.get())
	}
}

func TestSearchCancel(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	got := make(chan struct{}, 1)
	p.Handle(func(*fakeknx.Peer, fakeknx.Datagram) bool { got <- struct{}{}; return true })
	c, cancel := context.WithCancel(context.Background())
	go func() { <-got; cancel() }()
	if _, err := discovery.Search(c, discovery.WithUnicast(p.String()), discovery.WithTimeout(time.Minute)); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	// A context deadline before the timeout ends the search early,
	// without error.
	short, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()
	start := time.Now()
	rs, err := discovery.Search(short, discovery.WithUnicast(p.String()), discovery.WithTimeout(time.Minute))
	if time.Since(start) > 5*time.Second {
		t.Fatalf("took %v", time.Since(start))
	}
	// Whether the deadline is reported depends on which fires first, the
	// socket deadline or the context's timer (see the report).
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v", err)
	}
	if len(rs) != 0 {
		t.Fatalf("results %+v", rs)
	}
}

func TestResultEndpoint(t *testing.T) {
	from := netip.MustParseAddrPort("10.0.0.1:3671")
	r := discovery.Result{From: from, Control: knxnetip.RouteBackHPAI()}
	if r.Endpoint() != from {
		t.Fatalf("route back endpoint %s", r.Endpoint())
	}
	r.Control = knxnetip.NewHPAI(netip.MustParseAddrPort("10.0.0.2:3672"))
	if r.Endpoint().String() != "10.0.0.2:3672" {
		t.Fatalf("endpoint %s", r.Endpoint())
	}
	if r.Device().Name != "" || len(r.Services().Families) != 0 {
		t.Fatal("empty result has DIBs")
	}
}

func TestMulticastSearch(t *testing.T) {
	fakeknx.RequireMulticast(t)
	leak.Check(t)
	serial := [6]byte{0x00, 0xFA, 0xDE, 0xAD, 0xBE, 0xEF}
	sopts := []server.Option{server.WithDiscovery(true), server.WithSerial(serial), server.WithName("multicast")}
	dopts := []discovery.Option{discovery.WithTimeout(500 * time.Millisecond)}
	if lo := fakeknx.MulticastInterface(); lo != "" {
		sopts = append(sopts, server.WithInterface(lo))
		dopts = append(dopts, discovery.WithInterface(lo))
	}
	s := startServer(t, sopts...)
	rs, err := discovery.Search(ctx(t), dopts...)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.Device().Serial == serial {
			if r.Endpoint().Port() != s.Addr().Port() {
				t.Fatalf("endpoint %s, server %s", r.Endpoint(), s.Addr())
			}
			return
		}
	}
	t.Fatalf("server not found among %d results", len(rs))
}
