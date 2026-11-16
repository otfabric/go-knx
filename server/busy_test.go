// SPDX-License-Identifier: MIT

package server_test

import (
	"errors"
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
