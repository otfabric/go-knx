// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
)

// idleLink is a Link on which nothing arrives.
type idleLink struct{ closed chan struct{} }

func (l *idleLink) Send(context.Context, cemi.Frame) error { return nil }
func (l *idleLink) Receive(ctx context.Context) (cemi.Frame, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.closed:
		return nil, knx.ErrClosed
	}
}
func (l *idleLink) Close() error { close(l.closed); return nil }

// BenchmarkDeliver measures the delivery of one group telegram to the
// consumers of a client: one subscription, or a subscription, an
// OnTelegram callback and a pending read.
func BenchmarkDeliver(b *testing.B) {
	g := knx.MustParseGroupAddress("1/2/3")
	tpdu, err := apdu.GroupValueResponse(apdu.GroupValue{Data: []byte{0x0C, 0x1A}})
	if err != nil {
		b.Fatal(err)
	}
	frame := cemi.NewGroupFrame(cemi.LDataInd, 0x1105, g, knx.PriorityLow, tpdu)
	svc, v, err := apdu.ParseGroupValue(frame.TPDU)
	if err != nil {
		b.Fatal(err)
	}
	for _, bc := range []struct {
		name          string
		hook, pending bool
	}{
		{name: "subscription"},
		{name: "subscription+callback+read", hook: true, pending: true},
	} {
		b.Run(bc.name, func(b *testing.B) {
			c := New(&idleLink{closed: make(chan struct{})})
			defer c.Close()
			sub := c.Subscribe(1)
			if bc.hook {
				c.OnTelegram(func(Telegram) {})
			}
			w := &waiter{g: g, ch: make(chan Telegram, 1)}
			if bc.pending {
				c.mu.Lock()
				c.waiters[w] = struct{}{}
				c.mu.Unlock()
			}
			now := time.Now()
			b.ReportAllocs()
			for b.Loop() {
				c.deliver(Telegram{Time: now, Source: frame.Source, Group: g, Service: svc, Value: v, Frame: frame})
				<-sub.C()
				if bc.pending {
					<-w.ch
				}
			}
		})
	}
}
