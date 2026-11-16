// SPDX-License-Identifier: MIT

package routing_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/routing"
)

// Close contract 3: a Send after Close returns knx.ErrClosed and sends
// nothing, whether the send turn is free or not.
func TestSendAfterClose(t *testing.T) {
	leak.Check(t)
	c, m, _, _ := listen(t, routing.WithRate(0))
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		if err := c.Send(ctx(t), frame(byte(i))); !errors.Is(err, knx.ErrClosed) {
			t.Fatalf("Send %d after Close = %v, want knx.ErrClosed", i, err)
		}
	}
	if n := m.get(func(m *metrics) int { return m.sent }); n != 0 {
		t.Fatalf("%d frames sent after Close, want 0", n)
	}
	// A frame that would be refused is refused as closed too.
	f := frame(1)
	f.SetHopCount(0)
	if err := c.Send(ctx(t), f); !errors.Is(err, knx.ErrClosed) {
		t.Fatalf("Send of a frame with hop count 0 after Close = %v, want knx.ErrClosed", err)
	}
}

// WithMaxBusyPause bounds the pause after a ROUTING_BUSY: a frame that asks
// for a minute delays a Send by the ceiling.
func TestMaxBusyPause(t *testing.T) {
	leak.Check(t)
	for _, d := range []time.Duration{-time.Nanosecond, -time.Second} {
		if _, err := routing.Listen(ctx(t), routing.WithMaxBusyPause(d)); !errors.Is(err, knx.ErrInvalidOption) {
			t.Errorf("WithMaxBusyPause(%v) = %v, want knx.ErrInvalidOption", d, err)
		}
	}
	c, _, _, local := listen(t, routing.WithRate(0), routing.WithMaxBusyPause(100*time.Millisecond))
	p := fakeknx.Listen(t)
	p.Send(local, &knxnetip.RoutingBusy{WaitTime: 60000})
	recv(t, c.Events(), "the busy event")
	cx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	start := time.Now()
	if err := c.Send(cx, frame(1)); err != nil {
		t.Fatalf("Send after a ROUTING_BUSY of 60 s with a ceiling of 100 ms = %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Send returned after %v, want at most the ceiling of 100 ms", d)
	}
}
