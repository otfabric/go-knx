// SPDX-License-Identifier: MIT

//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package mcast

import (
	"errors"
	"syscall"
	"testing"
)

// The BSD multicast TTL option is one octet: values outside 0..255 are
// refused, not wrapped.
func TestSetTTLRange(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	for _, ttl := range []int{-1, 256} {
		if err := setTTL(uintptr(fd), ttl); !errors.Is(err, syscall.EINVAL) {
			t.Errorf("setTTL(%d) = %v, want EINVAL", ttl, err)
		}
	}
	if err := setTTL(uintptr(fd), 255); err != nil {
		t.Errorf("setTTL(255) = %v", err)
	}
}
