// SPDX-License-Identifier: MIT

package mcast_test

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/internal/mcast"
)

func TestListenAndConfigure(t *testing.T) {
	g := fakeknx.Group(t)
	c, err := mcast.Listen(nil, g, false, 4)
	if err != nil {
		t.Skipf("cannot join %s: %v", g, err)
	}
	defer c.Close()
	ip := netip.MustParseAddr("127.0.0.1")
	if err := mcast.Configure(c, &ip, true, 0); err != nil {
		t.Logf("set interface 127.0.0.1: %v", err) // not every system allows it
	}
	if err := mcast.Configure(c, nil, true, 1); err != nil {
		t.Fatal(err)
	}
	// A unicast datagram to the group port reaches the socket.
	s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.WriteToUDPAddrPort([]byte("x"), netip.AddrPortFrom(ip, g.Port())); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 8)
	if n, _, err := c.ReadFromUDPAddrPort(buf); err != nil || string(buf[:n]) != "x" {
		t.Fatalf("read %q %v", buf[:n], err)
	}
}

func TestListenErrors(t *testing.T) {
	if _, err := mcast.Listen(nil, netip.MustParseAddrPort("10.0.0.1:3671"), false, 1); err == nil {
		t.Fatal("joined a unicast address")
	}
	// Configure on a closed socket fails.
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if err := mcast.Configure(c, nil, false, 1); err == nil {
		t.Fatal("Configure on a closed socket succeeded")
	}
	// An address that is not the host's cannot be the multicast interface.
	c, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	bad := netip.MustParseAddr("192.0.2.77")
	if err := mcast.Configure(c, &bad, false, 1); err == nil {
		t.Fatal("Configure with a foreign interface address succeeded")
	}
}

func TestMulticastLoopback(t *testing.T) {
	fakeknx.RequireMulticast(t)
	g := fakeknx.Group(t)
	var ifi *net.Interface
	if name := fakeknx.MulticastInterface(); name != "" {
		ifi, _ = net.InterfaceByName(name)
	}
	r, err := mcast.Listen(ifi, g, true, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if ifi != nil {
		lo := netip.MustParseAddr("127.0.0.1")
		if err := mcast.Configure(r, &lo, true, 1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.WriteToUDPAddrPort([]byte("ping"), g); err != nil {
		t.Fatal(err)
	}
	_ = r.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 8)
	if n, _, err := r.ReadFromUDPAddrPort(buf); err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("read %q %v", buf[:n], err)
	}
}
