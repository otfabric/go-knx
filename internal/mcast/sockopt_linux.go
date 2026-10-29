// SPDX-License-Identifier: MIT

//go:build linux

package mcast

import "syscall"

func setInterface(fd uintptr, ip [4]byte) error {
	return syscall.SetsockoptInet4Addr(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, ip)
}

func setLoopback(fd uintptr, on bool) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, boolint(on))
}

func setTTL(fd uintptr, ttl int) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, ttl)
}

func boolint(b bool) int {
	if b {
		return 1
	}
	return 0
}
