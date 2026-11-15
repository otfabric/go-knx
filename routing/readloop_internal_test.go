// SPDX-License-Identifier: MIT

package routing

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/otfabric/go-knx"
)

// The read loop reads on after an error, but paused: 5 ms after the first
// error, doubling while errors follow each other, from 5 ms again after a
// datagram; and it ends when the Conn closes during a pause. The clock is
// the bubble's, so the pauses are exact.
func TestReadLoopPausesAfterErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := &Conn{o: options{logger: knx.NopLogger(), metrics: knx.NopMetrics{}}, closing: make(chan struct{})}
		start := time.Now()
		var calls []time.Duration
		// Six errors, a datagram that does not decode, then errors for ever.
		read := func(b []byte) (int, netip.AddrPort, error) {
			if len(calls) >= 1000 {
				// A loop that does not pause ends here and fails below.
				return 0, netip.AddrPort{}, net.ErrClosed
			}
			calls = append(calls, time.Since(start))
			if len(calls) == 7 {
				return copy(b, []byte{1, 2, 3}), netip.MustParseAddrPort("192.0.2.1:3671"), nil
			}
			return 0, netip.AddrPort{}, errors.New("no buffer space available")
		}
		c.wg.Add(1)
		go c.readLoop(read)
		time.Sleep(time.Second)
		synctest.Wait()
		ms := time.Millisecond
		want := []time.Duration{0, 5 * ms, 15 * ms, 35 * ms, 75 * ms, 155 * ms, 315 * ms, 315 * ms, 320 * ms, 330 * ms, 350 * ms, 390 * ms, 470 * ms, 630 * ms, 950 * ms}
		if len(calls) != len(want) {
			t.Fatalf("%d reads in the first second, the first at %v; want %d at %v", len(calls), calls[:min(len(calls), 16)], len(want), want)
		}
		for i := range want {
			if calls[i] != want[i] {
				t.Errorf("read %d at %v, want %v", i+1, calls[i], want[i])
			}
		}
		// The loop is in its next pause (640 ms): Close ends it at once.
		closed := time.Now()
		close(c.closing)
		c.wg.Wait()
		if d := time.Since(closed); d != 0 {
			t.Errorf("the loop ended %v after the Conn closed", d)
		}
		if len(calls) != len(want) {
			t.Errorf("%d reads after the Conn closed", len(calls)-len(want))
		}
	})
}

// A closed socket ends the loop without a pause.
func TestReadLoopEndsOnClosedSocket(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := &Conn{o: options{logger: knx.NopLogger(), metrics: knx.NopMetrics{}}, closing: make(chan struct{})}
		start := time.Now()
		c.wg.Add(1)
		go c.readLoop(func([]byte) (int, netip.AddrPort, error) { return 0, netip.AddrPort{}, net.ErrClosed })
		c.wg.Wait()
		if d := time.Since(start); d != 0 {
			t.Errorf("the loop ended after %v", d)
		}
	})
}
