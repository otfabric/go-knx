// SPDX-License-Identifier: MIT

package routing_test

import (
	"errors"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/routing"
)

// fakeClock is a clock the test advances; the reader of the Conn reads it.
type fakeClock struct{ ns atomic.Int64 }

func newFakeClock() *fakeClock {
	k := &fakeClock{}
	k.ns.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	return k
}

func (k *fakeClock) now() time.Time          { return time.Unix(0, k.ns.Load()) }
func (k *fakeClock) advance(d time.Duration) { k.ns.Add(int64(d)) }

// WithMaxBusyCount bounds the busy counter of the flow control: a series
// of ROUTING_BUSY frames, each more than 10 ms after the previous one,
// raises it to the ceiling and no further. Without the option, or with 0,
// every frame of the series counts.
func TestMaxBusyCount(t *testing.T) {
	leak.Check(t)
	for _, n := range []int{-1, math.MinInt} {
		if _, err := routing.Listen(ctx(t), routing.WithMaxBusyCount(n)); !errors.Is(err, knx.ErrInvalidOption) {
			t.Errorf("WithMaxBusyCount(%d) = %v, want knx.ErrInvalidOption", n, err)
		}
	}
	const series = 6
	for _, tc := range []struct {
		name string
		opts []routing.Option
		want int
	}{
		{"without the option", nil, series},
		{"0, no ceiling", []routing.Option{routing.WithMaxBusyCount(0)}, series},
		{"ceiling 1", []routing.Option{routing.WithMaxBusyCount(1)}, 1},
		{"ceiling below the series", []routing.Option{routing.WithMaxBusyCount(series - 1)}, series - 1},
		{"ceiling at the series", []routing.Option{routing.WithMaxBusyCount(series)}, series},
		{"ceiling above the series", []routing.Option{routing.WithMaxBusyCount(series + 1)}, series},
		{"ceiling MaxInt", []routing.Option{routing.WithMaxBusyCount(math.MaxInt)}, series},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, _, local := listen(t, append([]routing.Option{routing.WithRate(0)}, tc.opts...)...)
			k := newFakeClock()
			c.SetFlowClock(k.now)
			p := fakeknx.Listen(t)
			for range series {
				p.Send(local, &knxnetip.RoutingBusy{WaitTime: 10})
				recv(t, c.Events(), "the busy event")
				k.advance(20 * time.Millisecond)
			}
			if n := c.BusyCount(); n != tc.want {
				t.Fatalf("busy counter %d after %d ROUTING_BUSY frames, want %d", n, series, tc.want)
			}
		})
	}
}
