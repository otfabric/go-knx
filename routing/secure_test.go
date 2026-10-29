// SPDX-License-Identifier: MIT

package routing_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/routing"
	"github.com/otfabric/go-knx/secure"
)

var backbone = secure.Key{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

func inject(t *testing.T, to netip.AddrPort, m knxnetip.Message) {
	t.Helper()
	b, err := knxnetip.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(to))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(b); err != nil {
		t.Fatal(err)
	}
}

func wrapped(t *testing.T, key secure.Key, session uint16, timer uint64, v byte) *knxnetip.SecureWrapper {
	t.Helper()
	plain, err := knxnetip.Marshal(&knxnetip.RoutingIndication{CEMI: encoded(t, frame(v))})
	if err != nil {
		t.Fatal(err)
	}
	w, err := secure.Seal(key, session, timer, [6]byte{0, 0xfa, 9}, 0x1234, plain)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestSecureReceive(t *testing.T) {
	c, m, _, local := listen(t, routing.WithSecure(backbone, 100*time.Millisecond))
	// Accepted: a newer timer value.
	inject(t, local, wrapped(t, backbone, 0, 1<<40, 7))
	if f := receive(t, c); f.TPDU[len(f.TPDU)-1] != 7 {
		t.Fatalf("got %v", f)
	}
	inject(t, local, wrapped(t, secure.Key{9}, 0, 1<<40+10, 1))
	eventually(t, "decode error", func() bool { return m.get(func(m *metrics) int { return m.decode }) == 1 })
	inject(t, local, wrapped(t, backbone, 3, 1<<40+20, 1))
	eventually(t, "session drop", func() bool { return m.get(func(m *metrics) int { return m.dropped["session"] }) == 1 })
	inject(t, local, wrapped(t, backbone, 0, 5, 1))
	eventually(t, "timer drop", func() bool { return m.get(func(m *metrics) int { return m.dropped["timer"] }) == 1 })
	inject(t, local, &knxnetip.RoutingIndication{CEMI: encoded(t, frame(1))})
	eventually(t, "unsecured drop", func() bool { return m.get(func(m *metrics) int { return m.dropped["unsecured"] }) == 1 })
	inject(t, local, secure.NewTimerNotify(secure.Key{9}, 1, [6]byte{}, 1))
	eventually(t, "notify drop", func() bool { return m.get(func(m *metrics) int { return m.dropped["authentication"] }) == 1 })
	inject(t, local, secure.NewTimerNotify(backbone, 1<<41, [6]byte{}, 1))
	// A wrapper with a malformed frame inside.
	w, _ := secure.Seal(backbone, 0, 1<<42, [6]byte{}, 0, []byte{6, 0x10, 0x05, 0x30, 0, 0x50, 0})
	inject(t, local, w)
	eventually(t, "inner decode error", func() bool { return m.get(func(m *metrics) int { return m.decode }) == 2 })
	cx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if f, err := c.Receive(cx); err == nil {
		t.Fatalf("delivered %v", f)
	}
}

func TestSecureOptions(t *testing.T) {
	if _, err := routing.Listen(ctx(t), routing.WithSecure(backbone, -1)); !errors.Is(err, knx.ErrInvalidOption) {
		t.Errorf("negative latency: %v", err)
	}
}

func TestSecureMulticast(t *testing.T) {
	fakeknx.RequireMulticast(t)
	a, _, g, _ := listen(t, routing.WithLoopback(true), routing.WithSecure(backbone, 100*time.Millisecond), routing.WithSerialNumber([6]byte{0, 0xfa, 0, 0, 0, 1}))
	opts := []routing.Option{routing.WithGroup(g.String()), routing.WithLoopback(true), routing.WithSecure(backbone, 100*time.Millisecond)}
	if lo := fakeknx.MulticastInterface(); lo != "" {
		opts = append(opts, routing.WithInterface(lo))
	}
	b, err := routing.Listen(ctx(t), opts...)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	plainOpts := []routing.Option{routing.WithGroup(g.String()), routing.WithLoopback(true)}
	if lo := fakeknx.MulticastInterface(); lo != "" {
		plainOpts = append(plainOpts, routing.WithInterface(lo))
	}
	plain, err := routing.Listen(ctx(t), plainOpts...)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	for i := byte(1); i <= 3; i++ {
		if err := a.Send(ctx(t), frame(i)); err != nil {
			t.Fatal(err)
		}
		if f := receive(t, b); f.TPDU[len(f.TPDU)-1] != i {
			t.Fatalf("b got %v", f)
		}
	}
	if err := b.Send(ctx(t), frame(9)); err != nil {
		t.Fatal(err)
	}
	if f := receive(t, a); f.TPDU[len(f.TPDU)-1] != 9 {
		t.Fatalf("a got %v", f)
	}
	// A plain router neither reads secure frames nor gets its own read.
	if err := plain.Send(ctx(t), frame(5)); err != nil {
		t.Fatal(err)
	}
	cx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if f, err := plain.Receive(cx); err == nil {
		t.Fatalf("the plain router read %v", f)
	}
	if f, err := a.Receive(cx); err == nil {
		t.Fatalf("the secure router read a plain %v", f)
	}
}
