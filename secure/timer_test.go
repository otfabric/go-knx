// SPDX-License-Identifier: MIT

package secure

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-knx/knxnetip"
)

// bus connects routing timers like a multicast group.
type bus struct {
	mu     sync.Mutex
	timers []*RoutingTimer
	sent   []*knxnetip.TimerNotify
}

func (b *bus) add(t *testing.T, key Key, serial byte) *RoutingTimer {
	var r *RoutingTimer
	r = NewRoutingTimer(key, [6]byte{0, 0xfa, 0, 0, 0, serial}, 100*time.Millisecond, func(m *knxnetip.TimerNotify) {
		b.mu.Lock()
		b.sent = append(b.sent, m)
		others := append([]*RoutingTimer(nil), b.timers...)
		b.mu.Unlock()
		for _, o := range others {
			if o != r {
				go o.HandleNotify(m)
			}
		}
	})
	b.mu.Lock()
	b.timers = append(b.timers, r)
	b.mu.Unlock()
	t.Cleanup(r.Stop)
	return r
}

func TestRoutingTimerSynchronize(t *testing.T) {
	var k Key
	b := &bus{}
	keeper := b.add(t, k, 1)
	keeper.Synchronize(context.Background())
	if !keeper.Authenticated() || !keeper.TimeKeeper() {
		t.Fatal("an unanswered synchronisation makes a time keeper")
	}
	keeper.mu.Lock()
	keeper.offset += 1_000_000
	keeper.mu.Unlock()

	follower := b.add(t, k, 2)
	follower.Synchronize(context.Background())
	if follower.TimeKeeper() {
		t.Error("the follower became time keeper")
	}
	if d := int64(keeper.Next()) - int64(follower.Next()); d < -50 || d > 50 {
		t.Errorf("timers differ by %d ms", d)
	}

	// A wrapper with a newer timer advances the follower; one older than
	// the latency tolerance is refused.
	now := follower.Next()
	if !follower.Accept(&knxnetip.SecureWrapper{Sequence: put48(now + 5000)}) {
		t.Error("newer timer refused")
	}
	if v := follower.Next(); v < now+5000 {
		t.Errorf("timer %d not advanced to %d", v, now+5000)
	}
	if follower.Accept(&knxnetip.SecureWrapper{Sequence: put48(now)}) {
		t.Error("outdated timer accepted")
	}
	if !follower.Accept(&knxnetip.SecureWrapper{Sequence: put48(follower.Next() - 5)}) {
		t.Error("timer within the sync tolerance refused")
	}
	if !follower.Accept(&knxnetip.SecureWrapper{Sequence: put48(follower.Next() - 50)}) {
		t.Error("timer within the latency tolerance refused")
	}
}

func TestRoutingTimerNotify(t *testing.T) {
	var k Key
	r := NewRoutingTimer(k, [6]byte{1}, 0, func(*knxnetip.TimerNotify) {})
	defer r.Stop()
	if r.latency != DefaultLatency {
		t.Errorf("latency %v", r.latency)
	}
	bad := NewTimerNotify(Key{1}, 5, [6]byte{2}, 1)
	if r.HandleNotify(bad) {
		t.Error("notify under another key accepted")
	}
	r.mu.Lock()
	r.timekeeper = true
	r.mu.Unlock()
	if !r.HandleNotify(NewTimerNotify(k, r.Next()+100_000, [6]byte{2}, 1)) || r.TimeKeeper() {
		t.Error("a newer notify makes a follower")
	}
	// An outdated notify schedules an update notify.
	if !r.HandleNotify(NewTimerNotify(k, 0, [6]byte{2}, 1)) {
		t.Error("outdated notify refused")
	}
	r.mu.Lock()
	sched := r.schedUpdate
	r.mu.Unlock()
	if !sched {
		t.Error("no update scheduled")
	}
}

func TestRoutingTimerUpdateSent(t *testing.T) {
	var k Key
	got := make(chan *knxnetip.TimerNotify, 4)
	r := NewRoutingTimer(k, [6]byte{1}, 100*time.Millisecond, func(m *knxnetip.TimerNotify) { got <- m })
	defer r.Stop()
	r.mu.Lock()
	r.timekeeper, r.authenticated = true, true
	r.offset = 1_000_000
	r.mu.Unlock()
	r.HandleNotify(NewTimerNotify(k, 0, [6]byte{9}, 0xbeef))
	select {
	case m := <-got:
		if m.Serial != [6]byte{9} || m.MessageTag != 0xbeef || Uint48(m.Timer) < 1_000_000 {
			t.Errorf("update notify %+v", m)
		}
		if VerifyTimerNotify(k, m) != nil {
			t.Error("update notify MAC")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no update notify")
	}
	r.Stop()
	r.expired(r.gen, nil) // after Stop: nothing sent
	select {
	case m := <-got:
		t.Errorf("notify after stop: %+v", m)
	default:
	}
}

// TestRoutingTimerSaturates: a timer at the 48-bit maximum stays there.
// It used to wrap to the milliseconds elapsed since, values every peer
// refuses as outdated.
func TestRoutingTimerSaturates(t *testing.T) {
	var k Key
	r := NewRoutingTimer(k, [6]byte{1}, 0, func(*knxnetip.TimerNotify) {})
	defer r.Stop()
	if !r.HandleNotify(NewTimerNotify(k, MaxSequence, [6]byte{2}, 1)) {
		t.Fatal("notify refused")
	}
	time.Sleep(5 * time.Millisecond)
	if v := r.Next(); v != MaxSequence {
		t.Fatalf("timer %d after MaxSequence, want %d", v, uint64(MaxSequence))
	}
	if timerUint(-1) != 0 || timerInt(MaxSequence+1) != MaxSequence {
		t.Error("timer conversions out of range")
	}
}

func TestJitter(t *testing.T) {
	if jitter(0) != 0 || jitter(-1) != 0 {
		t.Error("jitter of an empty span")
	}
	for range 100 {
		if d := jitter(10 * time.Millisecond); d < 0 || d > 10*time.Millisecond {
			t.Fatalf("jitter %v outside [0, 10ms]", d)
		}
	}
}

// synchronized returns a timer that is synchronised as time keeper,
// without waiting for a synchronisation window.
func synchronized(t *testing.T, latency time.Duration) *RoutingTimer {
	t.Helper()
	r := NewRoutingTimer(Key{}, [6]byte{1}, latency, func(*knxnetip.TimerNotify) {})
	t.Cleanup(r.Stop)
	r.mu.Lock()
	r.timekeeper, r.authenticated = true, true
	r.offset = 1_000_000
	r.mu.Unlock()
	return r
}

// TestRoutingTimerAcceptRepeat: within the latency tolerance a wrapper
// is accepted once; other wrappers with the same timer value are not
// repeats.
func TestRoutingTimerAcceptRepeat(t *testing.T) {
	r := synchronized(t, time.Second)
	now := r.Next()
	w := &knxnetip.SecureWrapper{Sequence: put48(now - 20), Serial: [6]byte{0, 0xfa, 2}, MessageTag: 7, MAC: [16]byte{1}}
	if !r.Accept(w) {
		t.Fatal("first wrapper refused")
	}
	if r.Accept(w) {
		t.Error("repeated wrapper accepted")
	}
	other := []knxnetip.SecureWrapper{*w, *w, *w}
	other[0].MessageTag = 8
	other[1].Serial[5] = 1
	other[2].MAC[0] = 2
	for i := range other {
		if !r.Accept(&other[i]) {
			t.Errorf("wrapper %d with the same timer refused", i)
		}
		if r.Accept(&other[i]) {
			t.Errorf("wrapper %d accepted twice", i)
		}
	}
	// A newer wrapper advances the timer once; its repeat is refused.
	newer := &knxnetip.SecureWrapper{Sequence: put48(now + 5000), MessageTag: 1}
	if !r.Accept(newer) || r.Accept(newer) {
		t.Error("newer wrapper not accepted exactly once")
	}
}

// TestRoutingTimerAcceptBounded: the remembered wrappers are bounded;
// when the set is full of wrappers inside the tolerance new ones are
// refused, and they are accepted again once those leave the tolerance.
func TestRoutingTimerAcceptBounded(t *testing.T) {
	r := synchronized(t, time.Second)
	now := r.Next()
	for i := range maxSeenWrappers {
		w := &knxnetip.SecureWrapper{Sequence: put48(now), MessageTag: uint16(i)}
		if !r.Accept(w) {
			t.Fatalf("wrapper %d refused", i)
		}
	}
	extra := &knxnetip.SecureWrapper{Sequence: put48(now), MessageTag: 1, Serial: [6]byte{9}}
	if r.Accept(extra) {
		t.Error("wrapper accepted beyond the bound")
	}
	r.mu.Lock()
	r.offset += 2000
	n := len(r.seen)
	r.mu.Unlock()
	if n != maxSeenWrappers {
		t.Errorf("%d wrappers remembered", n)
	}
	fresh := &knxnetip.SecureWrapper{Sequence: put48(r.Next()), MessageTag: 1, Serial: [6]byte{9}}
	if !r.Accept(fresh) {
		t.Error("wrapper refused after the old ones expired")
	}
	r.mu.Lock()
	n = len(r.seen)
	r.mu.Unlock()
	if n != 1 {
		t.Errorf("%d wrappers remembered after expiry, want 1", n)
	}
}

// TestRoutingTimerSynchronizeNewest: the synchronisation takes the newest
// matching answer of its window, whatever the order, and accepts no
// wrapper before the window closes.
func TestRoutingTimerSynchronizeNewest(t *testing.T) {
	const newest = 50_000_000
	for _, order := range [][]uint64{{1000, newest}, {newest, 1000}} {
		var r *RoutingTimer
		done := make(chan struct{})
		var mid []string
		r = NewRoutingTimer(Key{}, [6]byte{0, 0xfa, 0, 0, 0, 1}, 100*time.Millisecond, func(m *knxnetip.TimerNotify) {
			if m.Serial != r.serial || Uint48(m.Timer) > 10_000 {
				return // only the synchronisation request
			}
			go func() {
				defer close(done)
				for _, v := range order {
					if !r.HandleNotify(NewTimerNotify(Key{}, v, r.serial, m.MessageTag)) {
						mid = append(mid, "answer refused")
					}
					if r.Authenticated() {
						mid = append(mid, "authenticated inside the window")
					}
					if r.Accept(&knxnetip.SecureWrapper{Sequence: put48(newest + 100)}) {
						mid = append(mid, "wrapper accepted inside the window")
					}
				}
			}()
		})
		start := time.Now()
		r.Synchronize(context.Background())
		<-done
		if d := time.Since(start); d < r.syncWindow() {
			t.Errorf("%v: returned after %v, window %v", order, d, r.syncWindow())
		}
		for _, s := range mid {
			t.Errorf("%v: %s", order, s)
		}
		if v := r.Next(); v < newest {
			t.Errorf("%v: timer %d, want >= %d", order, v, newest)
		}
		if r.TimeKeeper() || !r.Authenticated() {
			t.Errorf("%v: keeper %v, authenticated %v", order, r.TimeKeeper(), r.Authenticated())
		}
		r.Stop()
	}
}

// TestRoutingTimerNextIncreases: Next never returns the same value twice
// until the timer saturates.
func TestRoutingTimerNextIncreases(t *testing.T) {
	r := synchronized(t, 0)
	prev := r.Next()
	for range 1000 {
		v := r.Next()
		if v <= prev {
			t.Fatalf("Next %d after %d", v, prev)
		}
		prev = v
	}
	if !r.HandleNotify(NewTimerNotify(Key{}, MaxSequence, [6]byte{2}, 1)) {
		t.Fatal("notify refused")
	}
	if a, b := r.Next(), r.Next(); a != MaxSequence || b != MaxSequence {
		t.Errorf("saturated Next %d %d", a, b)
	}
}
