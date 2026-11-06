// SPDX-License-Identifier: MIT

// Package flowctl paces outgoing ROUTING_INDICATIONs: a minimum pause
// between consecutive indications and the reaction to ROUTING_BUSY of
// KNXnet/IP routing flow control (KNX 3/8/5 §2.3.5).
//
// The state is a busy counter N. A ROUTING_BUSY increments N when it
// arrives more than [BusyGap] after the previous one (the first one
// always counts), so that the copies several routers send for the same
// overload count once. Sending then pauses until at least the frame's
// wait time plus a random extension of up to N × [RandomStep] has
// passed; the random part spreads the senders that resume after the
// same busy frame. After the pause N stays for N × [SlowStep] (the slow
// duration), then drops by one every [DecayStep] until it reaches 0.
// While N > 0 after a pause the gap between indications is N + 1 times
// the normal gap, so a sender resumes at a reduced rate.
package flowctl

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"
)

// Timing of the flow control.
const (
	// BusyGap: ROUTING_BUSY frames at most this far apart count once.
	BusyGap = 10 * time.Millisecond
	// RandomStep is the random extension of the wait per count of N.
	RandomStep = 50 * time.Millisecond
	// SlowStep is the slow duration per count of N after the pause.
	SlowStep = 100 * time.Millisecond
	// DecayStep is the time after which N drops by one once the slow
	// duration has passed.
	DecayStep = 5 * time.Millisecond
	// TelegramTime is the gap unit while N > 0 when no rate is set:
	// about one telegram on a TP1 line (50 per second).
	TelegramTime = 20 * time.Millisecond
)

// Controller is the flow control state of one sender. A nil
// *Controller allows everything. It is safe for concurrent use.
type Controller struct {
	mu       sync.Mutex
	gap      time.Duration // minimum gap between indications, 0: none
	now      func() time.Time
	rand     func(limit time.Duration) time.Duration // uniform in [0, limit]
	n        int                                     // N as of pauseEnd
	lastBusy time.Time                               // last ROUTING_BUSY
	pauseEnd time.Time                               // end of the busy pause
	next     time.Time                               // earliest next send
}

// New returns a controller for rate indications per second (0: no
// minimum gap; ROUTING_BUSY is still honoured).
func New(rate int) *Controller {
	c := &Controller{now: time.Now, rand: cryptoRand}
	if rate > 0 {
		c.gap = time.Second / time.Duration(rate)
	}
	return c
}

// SetClock replaces the clock and the random source (tests). rnd
// returns a duration in [0, limit].
func (c *Controller) SetClock(now func() time.Time, rnd func(limit time.Duration) time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now, c.rand = now, rnd
}

func cryptoRand(limit time.Duration) time.Duration {
	if limit <= 0 {
		return 0
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	return time.Duration(binary.BigEndian.Uint64(b[:]) % uint64(limit+1))
}

// counter returns N at t: unchanged during the pause and the slow
// duration after it, then one less every DecayStep.
func (c *Controller) counter(t time.Time) int {
	if c.n == 0 || !t.After(c.pauseEnd) {
		return c.n
	}
	over := t.Sub(c.pauseEnd) - time.Duration(c.n)*SlowStep
	if over < 0 {
		return c.n
	}
	n := c.n - 1 - int(over/DecayStep)
	if n < 0 {
		return 0
	}
	return n
}

// Busy records a ROUTING_BUSY with the wait time it carries and returns
// the end of the resulting pause.
func (c *Controller) Busy(wait time.Duration) time.Time {
	if c == nil {
		return time.Time{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	n := c.counter(now)
	if c.lastBusy.IsZero() || now.Sub(c.lastBusy) > BusyGap {
		n++
	}
	c.lastBusy = now
	end := now.Add(wait + c.rand(time.Duration(n)*RandomStep))
	if end.After(c.pauseEnd) {
		c.pauseEnd = end
	}
	// N is kept as of the end of the pause; it does not decay before.
	c.n = n
	return c.pauseEnd
}

// Counter returns the current busy counter N.
func (c *Controller) Counter() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counter(c.now())
}

// Delay returns how long the sender must wait before the next
// indication (0: it may send now).
func (c *Controller) Delay() time.Duration {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	until := c.next
	if c.pauseEnd.After(until) {
		until = c.pauseEnd
	}
	if d := until.Sub(now); d > 0 {
		return d
	}
	return 0
}

// Sent records an indication sent now: the next one waits for the gap,
// N + 1 times longer while N > 0 after a busy pause.
func (c *Controller) Sent() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	gap := c.gap
	if n := c.counter(now); n > 0 {
		unit := c.gap
		if unit == 0 {
			unit = TelegramTime
		}
		gap = time.Duration(n+1) * unit
	}
	c.next = now.Add(gap)
}
