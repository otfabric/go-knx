// SPDX-License-Identifier: MIT

//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package mcast

import "syscall"

func setInterface(fd uintptr, ip [4]byte) error {
	return syscall.SetsockoptInet4Addr(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, ip)
}

func setLoopback(fd uintptr, on bool) error {
	v := byte(0)
	if on {
		v = 1
	}
	return syscall.SetsockoptByte(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, v)
}

func setTTL(fd uintptr, ttl int) error {
	return syscall.SetsockoptByte(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, byte(ttl))
}
