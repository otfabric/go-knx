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
