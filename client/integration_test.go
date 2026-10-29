// SPDX-License-Identifier: MIT

package client_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/client"
	"github.com/otfabric/go-knx/device"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/routing"
	"github.com/otfabric/go-knx/server"
	"github.com/otfabric/go-knx/tunnel"
)

func startServer(t testing.TB, devices ...*device.Device) *server.Server {
	t.Helper()
	s, err := server.New(server.WithListenAddr("127.0.0.1:0"), server.WithDiscovery(false),
		server.WithTunnelAddresses(knx.MustParseIndividualAddress("1.1.10"), knx.MustParseIndividualAddress("1.1.11")))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range devices {
		s.AddDevice(d)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func dialClient(t testing.TB, s *server.Server) *client.Client {
	t.Helper()
	c, err := client.DialTunnel(context.Background(), s.Addr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func object(t testing.TB, d *device.Device, name, id, flags string, v any, addrs ...string) *device.GroupObject {
	t.Helper()
	o, err := device.NewGroupObject(name, id, flags, addrs...)
	if err != nil {
		t.Fatal(err)
	}
	if v != nil {
		if err := o.Set(v); err != nil {
			t.Fatal(err)
		}
	}
	d.Add(o)
	return o
}

func TestOverServer(t *testing.T) {
	leak.Check(t)
	a1 := device.New("a1", knx.MustParseIndividualAddress("1.1.1"))
	a2 := device.New("a2", knx.MustParseIndividualAddress("1.1.2"))
	object(t, a1, "t", "9.001", "CR", 20.5, "1/2/4")
	object(t, a2, "t", "9.001", "CR", 22.5, "1/2/4")
	sw := object(t, a1, "sw", "1.001", "CW", nil, "1/2/3")
	s := startServer(t, a1, a2)
	c := dialClient(t, s)
	other := dialClient(t, s)
	sub := other.Subscribe(4, g1)

	if err := c.GroupWrite(ctx(t), g1, true); err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := sw.Value(); !ok || v != true {
		t.Fatalf("device value %v %v", v, ok)
	}
	select {
	case tg := <-sub.C():
		if v, _ := tg.Decode("1.001"); v != true || tg.Source != c.Link().(*tunnel.Conn).IndividualAddress() {
			t.Fatalf("telegram %+v", tg)
		}
	case <-time.After(wait):
		t.Fatal("subscriber saw nothing")
	}

	responses := c.Subscribe(8, g2)
	r, err := c.GroupRead(ctx(t), g2, client.WithDPT("9.001"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Decoded != 20.5 && r.Decoded != 22.5 {
		t.Fatalf("response %+v", r)
	}
	// Both devices answer; the second answer must not count for the next
	// read.
	for i := 0; i < 2; i++ {
		select {
		case <-responses.C():
		case <-time.After(wait):
			t.Fatal("second device did not answer")
		}
	}
	responses.Unsubscribe()
	rs, err := c.GroupReadAll(ctx(t), g2, 200*time.Millisecond, client.WithDPT("9.001"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 {
		t.Fatalf("%d responses: %+v", len(rs), rs)
	}
	short, cancel := context.WithTimeout(ctx(t), 100*time.Millisecond)
	defer cancel()
	if _, err := c.GroupRead(short, knx.MustParseGroupAddress("7/7/7")); !errors.Is(err, knx.ErrTimeout) {
		t.Fatalf("unanswered read: %v", err)
	}
	if err := c.GroupRespond(ctx(t), g1, false); err != nil {
		t.Fatal(err)
	}
}

func TestServerClosesLink(t *testing.T) {
	leak.Check(t)
	s := startServer(t)
	c := dialClient(t, s)
	sub := c.Subscribe(1)
	s.Close()
	select {
	case <-c.Done():
	case <-time.After(wait):
		t.Fatal("client not done after the server closed")
	}
	if !errors.Is(c.Err(), knx.ErrConnectionLost) {
		t.Fatalf("Err %v", c.Err())
	}
	if _, ok := <-sub.C(); ok {
		t.Fatal("subscription open")
	}
}

func TestDialErrors(t *testing.T) {
	leak.Check(t)
	if _, err := client.DialTunnel(ctx(t), "127.0.0.1:x", nil); !errors.Is(err, knx.ErrInvalidOption) {
		t.Fatalf("DialTunnel: %v", err)
	}
	if _, err := client.ListenRouting(ctx(t), []routing.Option{routing.WithGroup("10.0.0.1:3671")}); !errors.Is(err, knx.ErrInvalidOption) {
		t.Fatalf("ListenRouting: %v", err)
	}
}

func TestOverRouting(t *testing.T) {
	leak.Check(t)
	g := fakeknx.Group(t)
	ropts := []routing.Option{routing.WithGroup(g.String())}
	if lo := fakeknx.MulticastInterface(); lo != "" {
		ropts = append(ropts, routing.WithInterface(lo))
	}
	c, err := client.ListenRouting(ctx(t), ropts, client.WithSource(src))
	if err != nil {
		t.Skipf("cannot join %s: %v", g, err)
	}
	defer c.Close()
	// Sending needs no multicast reception; the frame goes out as an
	// L_Data.ind.
	if err := c.GroupWrite(ctx(t), g1, true); err != nil {
		t.Fatal(err)
	}
}

// BenchmarkGroupWrite measures a confirmed GroupWrite round trip over a
// loopback tunnel to the server.
func BenchmarkGroupWrite(b *testing.B) {
	s := startServer(b)
	c := dialClient(b, s)
	bg := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := c.GroupWrite(bg, g1, i%2 == 0); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "writes/s")
}
