// SPDX-License-Identifier: MIT

package server_test

import (
	"errors"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/knxnetip"
	"github.com/otfabric/go-knx/server"
)

// WithRoutingMaxBusyPause bounds the pause of the routing sender after a
// ROUTING_BUSY: a frame that asks for a minute holds the queued
// indications for the ceiling.
func TestRoutingMaxBusyPause(t *testing.T) {
	leak.Check(t)
	for _, d := range []time.Duration{-time.Nanosecond, -time.Second} {
		if _, err := server.New(server.WithRoutingMaxBusyPause(d)); !errors.Is(err, knx.ErrInvalidOption) {
			t.Errorf("WithRoutingMaxBusyPause(%v) = %v, want knx.ErrInvalidOption", d, err)
		}
	}
	s, m, _, local := startRouter(t, server.WithRoutingRate(0), server.WithRoutingMaxBusyPause(100*time.Millisecond))
	p := fakeknx.Listen(t)
	p.Send(local, &knxnetip.RoutingBusy{WaitTime: 60000})
	// The busy frame is handled by the reader; a description request
	// behind it tells when it has been.
	p.Send(local, &knxnetip.DescriptionRequest{Control: p.HPAI()})
	fakeknx.Expect[*knxnetip.DescriptionResponse](p, wait)
	if err := s.GroupWrite(ga, apdu.GroupValue{Data: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	// waitFrame fails the test when the indication is not sent within
	// 2 s; without the ceiling it would be sent after a minute.
	m.waitFrame(t, knxnetip.RoutingIndicationType)
}

// fakeClock is a clock the test advances; the reader of the server reads
// it.
type fakeClock struct{ ns atomic.Int64 }

func (k *fakeClock) now() time.Time          { return time.Unix(0, k.ns.Load()) }
func (k *fakeClock) advance(d time.Duration) { k.ns.Add(int64(d)) }

// WithRoutingMaxBusyCount bounds the busy counter of the routing sender:
// a series of ROUTING_BUSY frames, each more than 10 ms after the
// previous one, raises it to the ceiling and no further. Without the
// option, or with 0, every frame of the series counts.
func TestRoutingMaxBusyCount(t *testing.T) {
	leak.Check(t)
	for _, n := range []int{-1, math.MinInt} {
		if _, err := server.New(server.WithRoutingMaxBusyCount(n)); !errors.Is(err, knx.ErrInvalidOption) {
			t.Errorf("WithRoutingMaxBusyCount(%d) = %v, want knx.ErrInvalidOption", n, err)
		}
	}
	const series = 6
	for _, tc := range []struct {
		name string
		opts []server.Option
		want int
	}{
		{"without the option", nil, series},
		{"0, no ceiling", []server.Option{server.WithRoutingMaxBusyCount(0)}, series},
		{"ceiling 1", []server.Option{server.WithRoutingMaxBusyCount(1)}, 1},
		{"ceiling below the series", []server.Option{server.WithRoutingMaxBusyCount(series - 1)}, series - 1},
		{"ceiling at the series", []server.Option{server.WithRoutingMaxBusyCount(series)}, series},
		{"ceiling above the series", []server.Option{server.WithRoutingMaxBusyCount(series + 1)}, series},
		{"ceiling MaxInt", []server.Option{server.WithRoutingMaxBusyCount(math.MaxInt)}, series},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _, local := startRouter(t, append([]server.Option{server.WithRoutingRate(0)}, tc.opts...)...)
			k := &fakeClock{}
			k.ns.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
			s.SetFlowClock(k.now)
			p := fakeknx.Listen(t)
			for range series {
				p.Send(local, &knxnetip.RoutingBusy{WaitTime: 10})
				// The busy frame is handled by the reader; a description
				// request behind it tells when it has been.
				p.Send(local, &knxnetip.DescriptionRequest{Control: p.HPAI()})
				fakeknx.Expect[*knxnetip.DescriptionResponse](p, wait)
				k.advance(20 * time.Millisecond)
			}
			if n := s.BusyCount(); n != tc.want {
				t.Fatalf("busy counter %d after %d ROUTING_BUSY frames, want %d", n, series, tc.want)
			}
		})
	}
}
