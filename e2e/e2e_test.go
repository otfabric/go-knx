// SPDX-License-Identifier: MIT

// Package e2e tests go-knx end to end over real UDP sockets on the
// loopback interface: discovery, description, tunnelling clients and the
// server with virtual devices.
package e2e

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/client"
	"github.com/otfabric/go-knx/device"
	"github.com/otfabric/go-knx/discovery"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/server"
	"github.com/otfabric/go-knx/tunnel"
)

func startServer(t *testing.T, opts ...server.Option) (*server.Server, string) {
	t.Helper()
	opts = append([]server.Option{server.WithListenAddr("127.0.0.1:0"), server.WithDiscovery(false),
		server.WithTunnelAddresses(knx.MustParseIndividualAddress("1.1.10"), knx.MustParseIndividualAddress("1.1.11"))}, opts...)
	s, err := server.New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, s.Addr().String()
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestDescribe(t *testing.T) {
	_, addr := startServer(t, server.WithName("e2e"))
	dibs, err := discovery.Describe(ctx(t), addr)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := dibs.DeviceInfo()
	if !ok || d.Name != "e2e" || d.Medium != knxnetip.MediumIP {
		t.Fatalf("device info %+v", d)
	}
	if v, ok := mustFamilies(t, dibs).Version(knxnetip.FamilyTunnelling); !ok || v != 1 {
		t.Fatalf("tunnelling family %v %v", v, ok)
	}
}

func mustFamilies(t *testing.T, d knxnetip.DIBs) knxnetip.ServiceFamilies {
	f, ok := d.SupportedServices()
	if !ok {
		t.Fatal("no SUPP_SVC_FAMILIES")
	}
	return f
}

func TestDirectedSearch(t *testing.T) {
	_, addr := startServer(t)
	rs, err := discovery.Search(ctx(t), discovery.WithUnicast(addr), discovery.WithTimeout(500*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 || rs[0].Endpoint().String() != addr {
		t.Fatalf("results %+v", rs)
	}
	rs, err = discovery.Search(ctx(t), discovery.WithUnicast(addr), discovery.WithTimeout(500*time.Millisecond),
		discovery.WithExtended(knxnetip.SearchParam{Type: knxnetip.SRPRequestDIBs, Data: []byte{byte(knxnetip.DIBTunnellingInfo)}}))
	if err != nil || len(rs) != 1 || !rs[0].Extended {
		t.Fatalf("extended: %+v %v", rs, err)
	}
	if _, ok := rs[0].DIBs.Find(knxnetip.DIBTunnellingInfo); !ok {
		t.Fatalf("no TUNNELLING_INFO in %+v", rs[0].DIBs)
	}
}

func TestGroupCommunication(t *testing.T) {
	s, addr := startServer(t)
	dev := device.New("dev", knx.MustParseIndividualAddress("1.1.1"))
	temp, _ := device.NewGroupObject("temperature", "9.001", "CRT", "1/2/4")
	sw, _ := device.NewGroupObject("switch", "1.001", "CRWU", "1/2/3")
	dev.Add(temp, sw)
	_ = temp.Set(21.5)
	changes := make(chan device.Event, 4)
	dev.OnChange(func(e device.Event) { changes <- e })
	s.AddDevice(dev)

	c := ctx(t)
	a, err := client.DialTunnel(c, addr, []tunnel.Option{tunnel.WithHeartbeat(200*time.Millisecond, time.Second, 3)})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := client.DialTunnel(c, addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if a.Link().(*tunnel.Conn).IndividualAddress() == b.Link().(*tunnel.Conn).IndividualAddress() {
		t.Fatal("same tunnelling address")
	}
	sub := b.Subscribe(8, knx.MustParseGroupAddress("1/2/3"))

	if err := a.GroupWrite(c, knx.MustParseGroupAddress("1/2/3"), true); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-changes:
		if e.Value != true || e.Source != knx.MustParseIndividualAddress("1.1.10") {
			t.Fatalf("event %+v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("device saw no write")
	}
	select {
	case tg := <-sub.C():
		if v, _ := tg.Decode("1.001"); v != true {
			t.Fatalf("telegram %+v", tg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client b saw no write")
	}

	r, err := a.GroupRead(c, knx.MustParseGroupAddress("1/2/4"), client.WithDPT("9.001"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Decoded != 21.5 || r.Source != dev.Address {
		t.Fatalf("response %+v", r)
	}

	// No device answers 7/7/7.
	short, cancel := context.WithTimeout(c, 300*time.Millisecond)
	defer cancel()
	if _, err := a.GroupRead(short, knx.MustParseGroupAddress("7/7/7")); !errors.Is(err, knx.ErrTimeout) {
		t.Fatalf("read of an unanswered address: %v", err)
	}

	// A third client finds no free channel.
	if _, err := tunnel.Dial(c, addr); !errors.Is(err, knx.ErrBusy) {
		t.Fatalf("third connection: %v", err)
	}
	time.Sleep(500 * time.Millisecond) // heartbeats
	if len(s.Connections()) != 2 {
		t.Fatalf("connections %+v", s.Connections())
	}
}
