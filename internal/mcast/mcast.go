// SPDX-License-Identifier: MIT

// Package mcast opens the IPv4 multicast sockets of KNXnet/IP discovery
// and routing with the standard library only: joining a group, selecting
// the outgoing interface, the loopback and the TTL of multicast
// datagrams.
package mcast

import (
	"fmt"
	"net"
	"net/netip"
)

// Listen returns a socket bound to the wildcard address on group's port
// (reusable by other sockets) that has joined group on ifi (nil: the
// system's choice). Multicast it sends goes out on ifi with the given
// loopback and TTL.
func Listen(ifi *net.Interface, group netip.AddrPort, loopback bool, ttl int) (*net.UDPConn, error) {
	c, err := net.ListenMulticastUDP("udp4", ifi, net.UDPAddrFromAddrPort(group))
	if err != nil {
		return nil, fmt.Errorf("join %s: %w", group, err)
	}
	if err := Configure(c, nil, loopback, ttl); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// Configure sets the outgoing interface (when ip is valid), the loopback
// and the TTL (when ttl > 0) of the multicast datagrams sent on c.
func Configure(c *net.UDPConn, ip *netip.Addr, loopback bool, ttl int) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	err = rc.Control(func(fd uintptr) {
		if ip != nil && ip.Is4() {
			if serr = setInterface(fd, ip.As4()); serr != nil {
				return
			}
		}
		if serr = setLoopback(fd, loopback); serr != nil {
			return
		}
		if ttl > 0 {
			serr = setTTL(fd, ttl)
		}
	})
	if err != nil {
		return err
	}
	if serr != nil {
		return fmt.Errorf("multicast socket options: %w", serr)
	}
	return nil
}
