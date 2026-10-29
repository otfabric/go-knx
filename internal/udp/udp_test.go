// SPDX-License-Identifier: MIT

package udp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/otfabric/go-knx"
)

func TestResolveEndpoint(t *testing.T) {
	ctx := context.Background()
	for in, want := range map[string]string{
		"192.168.1.10":        "192.168.1.10:3671",
		"192.168.1.10:1234":   "192.168.1.10:1234",
		":5000":               "0.0.0.0:5000",
		"":                    "0.0.0.0:3671",
		"[::ffff:10.0.0.1]:7": "10.0.0.1:7",
		"localhost:9":         "127.0.0.1:9",
	} {
		got, err := ResolveEndpoint(ctx, in, 3671)
		if err != nil || got.String() != want {
			t.Errorf("ResolveEndpoint(%q) = %v, %v; want %s", in, got, err, want)
		}
	}
	for _, in := range []string{"1.2.3.4:x", "1.2.3.4:70000", "[::1]:3671", "::1", "no-such-host.invalid"} {
		if _, err := ResolveEndpoint(ctx, in, 3671); !errors.Is(err, knx.ErrInvalidOption) {
			t.Errorf("ResolveEndpoint(%q): %v, want ErrInvalidOption", in, err)
		}
	}
}

func TestLocalIPFor(t *testing.T) {
	ip, err := LocalIPFor(netip.MustParseAddrPort("127.0.0.1:3671"))
	if err != nil || ip != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("LocalIPFor(loopback) = %v, %v", ip, err)
	}
	if _, err := LocalIPFor(netip.AddrPort{}); err == nil {
		t.Fatal("LocalIPFor of an invalid endpoint succeeded")
	}
}

func loopback(t *testing.T) *net.Interface {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Skip(err)
	}
	for i := range ifs {
		if ifs[i].Flags&net.FlagLoopback != 0 {
			return &ifs[i]
		}
	}
	t.Skip("no loopback interface")
	return nil
}

func TestInterfaces(t *testing.T) {
	lo := loopback(t)
	ifi, ip, err := InterfaceIPv4(lo.Name)
	if err != nil || ifi.Name != lo.Name || !ip.IsLoopback() {
		t.Fatalf("InterfaceIPv4(%s) = %v %v %v", lo.Name, ifi, ip, err)
	}
	got, err := InterfaceForIP(ip)
	if err != nil || got.Name != lo.Name {
		t.Fatalf("InterfaceForIP(%s) = %v %v", ip, got, err)
	}
	if _, _, err := InterfaceIPv4("no-such-interface0"); !errors.Is(err, knx.ErrInvalidOption) {
		t.Fatalf("unknown interface: %v", err)
	}
	if _, err := InterfaceForIP(netip.MustParseAddr("192.0.2.123")); !errors.Is(err, knx.ErrInvalidOption) {
		t.Fatalf("unknown address: %v", err)
	}
	// An interface without IPv4 address, if there is one.
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		addrs, _ := i.Addrs()
		has4 := false
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
				has4 = true
			}
		}
		if !has4 {
			if _, _, err := InterfaceIPv4(i.Name); !errors.Is(err, knx.ErrInvalidOption) {
				t.Fatalf("interface %s without IPv4: %v", i.Name, err)
			}
			break
		}
	}
}

func TestAddrPortOf(t *testing.T) {
	a := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5}
	if got := AddrPortOf(a); got.String() != "10.0.0.1:5" {
		t.Fatalf("AddrPortOf = %v", got)
	}
	if got := AddrPortOf(&net.TCPAddr{}); got.IsValid() {
		t.Fatalf("AddrPortOf(TCP) = %v", got)
	}
}
