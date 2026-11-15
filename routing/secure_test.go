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
	"github.com/otfabric/go-knx/internal/leak"
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

// L5 and L14: Listen with WithSecure returns after the whole timer
// synchronisation window. A context that ends inside the window ends
// Listen with the context's error: no Conn, no goroutine and no socket are
// left.
func TestSecureListenContextEnds(t *testing.T) {
	leak.Check(t)
	_, _, g, _ := listen(t) // skips where the group cannot be joined
	opts := []routing.Option{routing.WithGroup(g.String()), routing.WithSecure(backbone, 100*time.Millisecond)}
	if lo := fakeknx.MulticastInterface(); lo != "" {
		opts = append(opts, routing.WithInterface(lo))
	}
	for name, tc := range map[string]struct {
		ctx  func() (context.Context, context.CancelFunc)
		want error
	}{
		// The window is 420 ms at this latency.
		"deadline": {func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 20*time.Millisecond)
		}, context.DeadlineExceeded},
		"cancelled": {func() (context.Context, context.CancelFunc) {
			cx, cancel := context.WithCancel(context.Background())
			cancel()
			return cx, cancel
		}, context.Canceled},
	} {
		t.Run(name, func(t *testing.T) {
			before := openFDs()
			cx, cancel := tc.ctx()
			defer cancel()
			c, err := routing.Listen(cx, opts...)
			if c != nil {
				c.Close()
				t.Fatalf("Listen returned a Conn and %v although its context ended inside the synchronisation window", err)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Listen = %v, want an error matching %v", err, tc.want)
			}
			if after := openFDs(); before >= 0 && after != before {
				t.Errorf("%d descriptors open after the failed Listen, %d before", after, before)
			}
		})
	}
	// With a context that lasts, the same options give a Conn.
	c, err := routing.Listen(ctx(t), opts...)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
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
