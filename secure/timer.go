// SPDX-License-Identifier: MIT

package secure

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/otfabric/go-knx/knxnetip"
)

// Delays of the timer synchronisation of secure routing. They follow
// xknx's reading of KNX IP Secure 3/8/9 §2.2.2.3: a time keeper sends a
// periodic TIMER_NOTIFY every 10 s, followers wait a little longer before
// they take over, and an update notify answers an outdated timer value.
const (
	minDelayKeeperPeriodic = 10 * time.Second
	minDelayKeeperUpdate   = 100 * time.Millisecond
	syncLatencyPercent     = 10
)

// DefaultLatency is the latency tolerance of secure routing when the
// keyring gives none.
const DefaultLatency = time.Second

// RoutingTimer is the synchronised timer of secure routing: the sequence
// information of every multicast SECURE_WRAPPER. It sends TIMER_NOTIFY
// frames through the send function, as time keeper or follower.
type RoutingTimer struct {
	key     Key
	serial  [6]byte
	latency time.Duration
	syncTol time.Duration
	send    func(*knxnetip.TimerNotify)
	start   time.Time

	mu            sync.Mutex
	offset        int64 // timer value minus local milliseconds
	timekeeper    bool
	schedUpdate   bool
	authenticated bool
	expect        *expectedNotify
	t             *time.Timer
	gen           uint64
	stopped       bool
}

type expectedNotify struct {
	tag uint16
	ch  chan uint64
}

// NewRoutingTimer returns a timer for the backbone key. serial is the
// KNX serial number of this router; latency is the latency tolerance of
// the backbone (keyring attribute Latency), 0 for DefaultLatency.
func NewRoutingTimer(key Key, serial [6]byte, latency time.Duration, send func(*knxnetip.TimerNotify)) *RoutingTimer {
	if latency <= 0 {
		latency = DefaultLatency
	}
	return &RoutingTimer{key: key, serial: serial, latency: latency, syncTol: latency * syncLatencyPercent / 100, send: send, start: time.Now()}
}

func (r *RoutingTimer) localMS() int64 { return time.Since(r.start).Milliseconds() }

// value returns the timer value; r.mu must be held.
func (r *RoutingTimer) value() uint64 { return uint64(r.localMS()+r.offset) & MaxSequence }

func (r *RoutingTimer) delays(update bool) (lo, hi time.Duration) {
	keeperPeriodicMax := minDelayKeeperPeriodic + 3*r.syncTol
	keeperUpdateMax := minDelayKeeperUpdate + r.syncTol
	switch {
	case update && r.timekeeper:
		return minDelayKeeperUpdate, keeperUpdateMax
	case update:
		lo = keeperUpdateMax + r.syncTol
		return lo, lo + 10*r.syncTol
	case r.timekeeper:
		return minDelayKeeperPeriodic, keeperPeriodicMax
	default:
		lo = keeperPeriodicMax + r.syncTol
		return lo, lo + 10*r.syncTol
	}
}

// Synchronize sends a TIMER_NOTIFY and waits for the time keeper's
// answer; without one this router becomes the time keeper. Frames are
// accepted only after it returns.
func (r *RoutingTimer) Synchronize(ctx context.Context) {
	tag := uint16(rand.Uint32())
	e := &expectedNotify{tag: tag, ch: make(chan uint64, 1)}
	r.mu.Lock()
	r.expect = e
	v := r.value()
	r.mu.Unlock()
	r.send(NewTimerNotify(r.key, v, r.serial, tag))
	_, hi := r.delays(true)
	t := time.NewTimer(hi + 2*r.latency)
	defer t.Stop()
	var got uint64
	ok := false
	select {
	case got = <-e.ch:
		ok = true
	case <-t.C:
	case <-ctx.Done():
	}
	r.mu.Lock()
	r.expect = nil
	if ok {
		r.offset = int64(got) - r.localMS()
	} else {
		r.timekeeper = true
	}
	r.authenticated = true
	r.reschedule(nil)
	r.mu.Unlock()
}

// Authenticated reports whether the timer is synchronised.
func (r *RoutingTimer) Authenticated() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.authenticated
}

// TimeKeeper reports whether this router is the time keeper.
func (r *RoutingTimer) TimeKeeper() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.timekeeper
}

// Next returns the timer value for an outgoing SECURE_WRAPPER.
func (r *RoutingTimer) Next() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.schedUpdate {
		r.reschedule(nil)
	}
	return r.value()
}

// Accept checks the timer value of a received SECURE_WRAPPER (already
// authenticated): a newer value advances the timer, a value older than
// the latency tolerance is refused and answered by an update notify.
func (r *RoutingTimer) Accept(w *knxnetip.SecureWrapper) bool {
	recv := int64(Uint48(w.Sequence))
	r.mu.Lock()
	defer r.mu.Unlock()
	local := int64(r.value())
	switch {
	case recv > local:
		r.offset += recv - local
		if !r.schedUpdate {
			r.reschedule(nil)
		}
		return true
	case recv > local-r.syncTol.Milliseconds():
		if !r.schedUpdate {
			r.reschedule(nil)
		}
		return true
	case recv > local-r.latency.Milliseconds():
		return true
	}
	if !r.schedUpdate {
		r.reschedule(&update{tag: w.MessageTag, serial: w.Serial})
	}
	return false
}

// HandleNotify processes a received TIMER_NOTIFY. It returns false when
// the MAC is wrong.
func (r *RoutingTimer) HandleNotify(m *knxnetip.TimerNotify) bool {
	if VerifyTimerNotify(r.key, m) != nil {
		return false
	}
	recv := int64(Uint48(m.Timer))
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.expect; e != nil && m.Serial == r.serial && m.MessageTag == e.tag {
		select {
		case e.ch <- uint64(recv):
		default:
		}
		return true
	}
	local := int64(r.value())
	switch {
	case recv > local:
		r.offset += recv - local
		r.timekeeper = false
		r.reschedule(nil)
	case recv > local-r.syncTol.Milliseconds():
		r.timekeeper = false
		r.reschedule(nil)
	case recv > local-r.latency.Milliseconds():
	default:
		if !r.schedUpdate {
			r.reschedule(&update{tag: m.MessageTag, serial: m.Serial})
		}
	}
	return true
}

type update struct {
	tag    uint16
	serial [6]byte
}

// reschedule (re)starts the notify timer; r.mu must be held.
func (r *RoutingTimer) reschedule(u *update) {
	if r.stopped {
		return
	}
	if r.t != nil {
		r.t.Stop()
	}
	r.schedUpdate = u != nil
	lo, hi := r.delays(u != nil)
	d := lo + time.Duration(rand.Int64N(int64(hi-lo)+1))
	r.gen++
	gen := r.gen
	r.t = time.AfterFunc(d, func() { r.expired(gen, u) })
}

func (r *RoutingTimer) expired(gen uint64, u *update) {
	r.mu.Lock()
	if r.stopped || gen != r.gen {
		r.mu.Unlock()
		return
	}
	serial, tag := r.serial, uint16(rand.Uint32())
	if u != nil {
		serial, tag = u.serial, u.tag
	}
	m := NewTimerNotify(r.key, r.value(), serial, tag)
	r.timekeeper = true
	r.reschedule(nil)
	r.mu.Unlock()
	r.send(m)
}

// Stop stops the notify timer.
func (r *RoutingTimer) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopped = true
	if r.t != nil {
		r.t.Stop()
	}
}
