// SPDX-License-Identifier: MIT

//go:build windows

package mcast

import "syscall"

func setInterface(fd uintptr, ip [4]byte) error {
	return syscall.SetsockoptInet4Addr(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, ip)
}

func setLoopback(fd uintptr, on bool) error {
	v := 0
	if on {
		v = 1
	}
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, v)
}

func setTTL(fd uintptr, ttl int) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, ttl)
}
