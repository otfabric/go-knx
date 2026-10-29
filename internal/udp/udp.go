// SPDX-License-Identifier: MIT

// Package udp holds the UDP helpers shared by the KNXnet/IP client,
// discovery, routing and server code.
package udp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/otfabric/go-knx"
)

// ResolveEndpoint parses "host", "host:port" or ":port" into an IPv4
// endpoint, defaulting the port to defPort. Host names are resolved.
func ResolveEndpoint(ctx context.Context, s string, defPort uint16) (netip.AddrPort, error) {
	host, port := s, strconv.Itoa(int(defPort))
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
	}
	pn, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: endpoint %q: bad port", knx.ErrInvalidOption, s)
	}
	if host == "" {
		return netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(pn)), nil
	}
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		if !a.Is4() {
			return netip.AddrPort{}, fmt.Errorf("%w: endpoint %q: KNXnet/IP uses IPv4", knx.ErrInvalidOption, s)
		}
		return netip.AddrPortFrom(a, uint16(pn)), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("%w: endpoint %q: %v", knx.ErrInvalidOption, s, err)
	}
	return netip.AddrPortFrom(ips[0].Unmap(), uint16(pn)), nil
}

// LocalIPFor returns the local IPv4 address the system routes to remote
// from (no packet is sent).
func LocalIPFor(remote netip.AddrPort) (netip.Addr, error) {
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(remote))
	if err != nil {
		return netip.Addr{}, err
	}
	defer func() { _ = c.Close() }()
	ap := c.LocalAddr().(*net.UDPAddr).AddrPort()
	return ap.Addr().Unmap(), nil
}

// InterfaceIPv4 returns the first IPv4 address of the named interface.
func InterfaceIPv4(name string) (*net.Interface, netip.Addr, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, netip.Addr{}, fmt.Errorf("%w: interface %q: %v", knx.ErrInvalidOption, name, err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, netip.Addr{}, err
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap().Is4() {
				return ifi, ip.Unmap(), nil
			}
		}
	}
	return nil, netip.Addr{}, fmt.Errorf("%w: interface %q has no IPv4 address", knx.ErrInvalidOption, name)
}

// InterfaceForIP returns the interface that has address ip.
func InterfaceForIP(ip netip.Addr) (*net.Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for i := range ifs {
		addrs, _ := ifs[i].Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if x, ok := netip.AddrFromSlice(n.IP); ok && x.Unmap() == ip {
					return &ifs[i], nil
				}
			}
		}
	}
	return nil, fmt.Errorf("%w: no interface has address %s", knx.ErrInvalidOption, ip)
}

// AddrPortOf returns the endpoint of a *net.UDPAddr (IPv4-mapped
// addresses unmapped).
func AddrPortOf(a net.Addr) netip.AddrPort {
	if u, ok := a.(*net.UDPAddr); ok {
		ap := u.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return netip.AddrPort{}
}
