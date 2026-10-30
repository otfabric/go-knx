// SPDX-License-Identifier: MIT

package server

import (
	"errors"
	"net"
	"net/netip"
	"testing"
)

// A port that is free for TCP and not for UDP is given up for another.
func TestEphemeralUDPTCPRetries(t *testing.T) {
	listen := netip.MustParseAddrPort("127.0.0.1:0")
	taken := errors.New("taken")
	calls := 0
	c, ln, err := ephemeralUDPTCP(listen, func(n string, a *net.UDPAddr) (*net.UDPConn, error) {
		if calls++; calls < 3 {
			return nil, taken
		}
		return net.ListenUDP(n, a)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close(); _ = ln.Close() }()
	if calls != 3 {
		t.Fatalf("%d tries", calls)
	}
	if u, l := c.LocalAddr().(*net.UDPAddr).Port, ln.Addr().(*net.TCPAddr).Port; u != l {
		t.Fatalf("UDP port %d, TCP port %d", u, l)
	}
}

func TestEphemeralUDPTCPGivesUp(t *testing.T) {
	taken := errors.New("taken")
	_, _, err := ephemeralUDPTCP(netip.MustParseAddrPort("127.0.0.1:0"), func(string, *net.UDPAddr) (*net.UDPConn, error) {
		return nil, taken
	})
	if !errors.Is(err, taken) {
		t.Fatalf("got %v", err)
	}
}
