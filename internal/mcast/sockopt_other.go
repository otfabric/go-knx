// SPDX-License-Identifier: MIT

//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !windows

package mcast

func setInterface(uintptr, [4]byte) error { return nil }
func setLoopback(uintptr, bool) error     { return nil }
func setTTL(uintptr, int) error           { return nil }
