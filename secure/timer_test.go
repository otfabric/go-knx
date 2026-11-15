// SPDX-License-Identifier: MIT

package secure

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/otfabric/go-knx/knxnetip"
)

// window returns the synchronisation window of r.
func window(r *RoutingTimer) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.syncWindow()
}

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
	synctest.Test(t, func(t *testing.T) {
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
	})
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
	synctest.Test(t, func(t *testing.T) {
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
	})
}

// TestRoutingTimerSaturates: a timer at the 48-bit maximum stays there.
// It used to wrap to the milliseconds elapsed since, values every peer
// refuses as outdated.
func TestRoutingTimerSaturates(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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
	})
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
	synctest.Test(t, func(t *testing.T) {
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
			if d := time.Since(start); d != window(r) {
				t.Errorf("%v: returned after %v, window %v", order, d, window(r))
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
	})
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

// The clock of the tests above and below is the bubble's (testing/synctest):
// a synchronisation window, a notify delay or a pause takes no real time
// and ends at an exact instant.

// TestRoutingTimerSynchronizeWindow: a synchronisation counts only when
// its whole window has passed. When the context ends before that, the
// timer stays unsynchronised: it accepts nothing, the router is not time
// keeper and no periodic notify is scheduled. A later Synchronize with a
// context that lasts completes.
func TestRoutingTimerSynchronizeWindow(t *testing.T) {
	const latency = 100 * time.Millisecond
	for _, tc := range []struct {
		name  string
		ctx   func(window time.Duration) (context.Context, context.CancelFunc)
		whole bool
	}{
		{"ended before the call", func(time.Duration) (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, cancel
		}, false},
		{"deadline at the start of the window", func(time.Duration) (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), time.Nanosecond)
		}, false},
		{"deadline a millisecond before the end", func(w time.Duration) (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), w-time.Millisecond)
		}, false},
		{"deadline a millisecond after the end", func(w time.Duration) (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), w+time.Millisecond)
		}, true},
		{"no deadline", func(time.Duration) (context.Context, context.CancelFunc) {
			return context.WithCancel(context.Background())
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var notifies atomic.Int32
				r := NewRoutingTimer(Key{}, [6]byte{0, 0xfa, 0, 0, 0, 1}, latency, func(*knxnetip.TimerNotify) { notifies.Add(1) })
				defer r.Stop()
				ctx, cancel := tc.ctx(window(r))
				defer cancel()
				r.Synchronize(ctx)
				newer := &knxnetip.SecureWrapper{Sequence: put48(1 << 40), MessageTag: 1}
				if got := r.Authenticated(); got != tc.whole {
					t.Fatalf("Authenticated() = %t, want %t", got, tc.whole)
				}
				if got := r.TimeKeeper(); got != tc.whole {
					t.Errorf("TimeKeeper() = %t, want %t", got, tc.whole)
				}
				if got := r.Accept(newer); got != tc.whole {
					t.Errorf("Accept of a wrapper with a newer timer = %t, want %t", got, tc.whole)
				}
				// The periodic notify of a time keeper comes within 11 s.
				time.Sleep(time.Minute)
				synctest.Wait()
				if got := notifies.Load(); (got > 1) != tc.whole {
					t.Errorf("%d notifies sent a minute later (the first is the synchronisation request)", got)
				}
				if tc.whole {
					return
				}
				// The same timer synchronises once a context lasts.
				r.Synchronize(context.Background())
				if !r.Authenticated() || !r.TimeKeeper() {
					t.Errorf("second synchronisation: authenticated %t, time keeper %t", r.Authenticated(), r.TimeKeeper())
				}
				if !r.Accept(&knxnetip.SecureWrapper{Sequence: put48(1 << 41), MessageTag: 2}) {
					t.Error("a wrapper with a newer timer refused after the second synchronisation")
				}
			})
		})
	}
}

// TestRoutingTimerAnswerInShortWindow: an answer that arrived in a window
// the context cut short has raised the timer, and the next
// synchronisation starts from there.
func TestRoutingTimerAnswerInShortWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const keeper = 77_000_000
		var r *RoutingTimer
		r = NewRoutingTimer(Key{}, [6]byte{0, 0xfa, 0, 0, 0, 1}, 100*time.Millisecond, func(m *knxnetip.TimerNotify) {
			if m.Serial == r.serial && Uint48(m.Timer) < keeper {
				go r.HandleNotify(NewTimerNotify(Key{}, keeper, r.serial, m.MessageTag))
			}
		})
		defer r.Stop()
		ctx, cancel := context.WithTimeout(context.Background(), window(r)/2)
		defer cancel()
		r.Synchronize(ctx)
		if r.Authenticated() || r.TimeKeeper() {
			t.Fatalf("after half a window: authenticated %t, time keeper %t", r.Authenticated(), r.TimeKeeper())
		}
		if v := r.Next(); v < keeper {
			t.Errorf("timer %d, want at least the answer's %d", v, keeper)
		}
	})
}

// TestRoutingTimerStopWaitsForNotify: Stop returns only when a notify the
// timer is sending has been sent, and the timer sends nothing after it.
func TestRoutingTimerStopWaitsForNotify(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var sends atomic.Int32
		sending, release := make(chan struct{}), make(chan struct{})
		r := NewRoutingTimer(Key{}, [6]byte{0, 0xfa, 0, 0, 0, 1}, 100*time.Millisecond, func(*knxnetip.TimerNotify) {
			if sends.Add(1) == 2 { // the first is the synchronisation request
				close(sending)
				<-release
			}
		})
		r.Synchronize(context.Background())
		<-sending // the periodic notify of the time keeper
		stopped := make(chan struct{})
		go func() {
			r.Stop()
			close(stopped)
		}()
		synctest.Wait()
		select {
		case <-stopped:
			t.Fatal("Stop returned while the timer was sending a notify")
		default:
		}
		close(release)
		<-stopped
		time.Sleep(time.Minute)
		synctest.Wait()
		if n := sends.Load(); n != 2 {
			t.Errorf("%d notifies sent, want 2: none after Stop", n)
		}
		r.Stop() // a second Stop returns
	})
}
