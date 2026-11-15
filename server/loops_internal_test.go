// SPDX-License-Identifier: MIT

package server

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

// The loops that accept connections and read sockets go on after an
// error, but paused: 5 ms after the first error, doubling while errors
// follow each other up to 1 s, from 5 ms again after a success; and they
// end when the server closes during a pause. The clock is the bubble's
// (testing/synctest), so the pauses are exact.

// maxLoopCalls ends a loop that does not pause, so that such a loop fails
// its test with a count and not with a timeout.
const maxLoopCalls = 1000

var loopPauses = []time.Duration{
	0, 5 * time.Millisecond, 15 * time.Millisecond, 35 * time.Millisecond, 75 * time.Millisecond, 155 * time.Millisecond,
	315 * time.Millisecond, 635 * time.Millisecond, 1275 * time.Millisecond, 2275 * time.Millisecond, 3275 * time.Millisecond,
}

func TestAcceptLoopPausesAfterErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, err := New()
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		var calls []time.Duration
		full := &net.OpError{Op: "accept", Net: "tcp4", Err: syscall.EMFILE}
		s.wg.Add(1)
		go s.acceptLoop(func() (*net.TCPConn, error) {
			if len(calls) >= maxLoopCalls {
				return nil, net.ErrClosed
			}
			calls = append(calls, time.Since(start))
			return nil, full
		})
		time.Sleep(4 * time.Second)
		synctest.Wait()
		if len(calls) != len(loopPauses) {
			t.Fatalf("%d accepts in four seconds, the first at %v; want %d at %v", len(calls), calls[:min(len(calls), 12)], len(loopPauses), loopPauses)
		}
		for i, want := range loopPauses {
			if calls[i] != want {
				t.Errorf("accept %d at %v, want %v", i+1, calls[i], want)
			}
		}
		// The loop is in a pause of a second: Close ends it at once.
		closed := time.Now()
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if d := time.Since(closed); d != 0 {
			t.Errorf("Close returned %v after it was called", d)
		}
		if len(calls) != len(loopPauses) {
			t.Errorf("%d accepts after Close", len(calls)-len(loopPauses))
		}
	})
}

func TestAcceptLoopEndsOnClosedListener(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, err := New()
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		s.wg.Add(1)
		go s.acceptLoop(func() (*net.TCPConn, error) { return nil, net.ErrClosed })
		s.wg.Wait()
		if d := time.Since(start); d != 0 {
			t.Errorf("the loop ended after %v", d)
		}
	})
}

func TestReadLoopPausesAfterErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, err := New()
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		var calls []time.Duration
		// Four errors, a datagram (which does not decode and is dropped),
		// then errors for ever: the datagram starts the pauses again.
		s.wg.Add(1)
		go s.readLoop(func(b []byte) (int, netip.AddrPort, error) {
			if len(calls) >= maxLoopCalls {
				return 0, netip.AddrPort{}, net.ErrClosed
			}
			calls = append(calls, time.Since(start))
			if len(calls) == 5 {
				return copy(b, []byte{1, 2, 3}), netip.MustParseAddrPort("192.0.2.1:3671"), nil
			}
			return 0, netip.AddrPort{}, errors.New("no buffer space available")
		})
		time.Sleep(200 * time.Millisecond)
		synctest.Wait()
		ms := time.Millisecond
		want := []time.Duration{0, 5 * ms, 15 * ms, 35 * ms, 75 * ms, 75 * ms, 80 * ms, 90 * ms, 110 * ms, 150 * ms}
		if len(calls) != len(want) {
			t.Fatalf("%d reads in 200 ms, the first at %v; want %d at %v", len(calls), calls[:min(len(calls), 12)], len(want), want)
		}
		for i := range want {
			if calls[i] != want[i] {
				t.Errorf("read %d at %v, want %v", i+1, calls[i], want[i])
			}
		}
		closed := time.Now()
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if d := time.Since(closed); d != 0 {
			t.Errorf("Close returned %v after it was called", d)
		}
		if len(calls) != len(want) {
			t.Errorf("%d reads after Close", len(calls)-len(want))
		}
	})
}

func TestReadLoopEndsOnClosedSocket(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, err := New()
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		s.wg.Add(1)
		go s.readLoop(func([]byte) (int, netip.AddrPort, error) { return 0, netip.AddrPort{}, net.ErrClosed })
		s.wg.Wait()
		if d := time.Since(start); d != 0 {
			t.Errorf("the loop ended after %v", d)
		}
	})
}
