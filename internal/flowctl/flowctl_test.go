// SPDX-License-Identifier: MIT

package flowctl

import (
	"testing"
	"time"
)

// clock is a manual clock and a recording random source that returns
// the largest allowed value scaled by frac.
type clock struct {
	t     time.Time
	frac  float64
	asked []time.Duration
}

func (k *clock) now() time.Time { return k.t }
func (k *clock) rand(limit time.Duration) time.Duration {
	k.asked = append(k.asked, limit)
	return time.Duration(float64(limit) * k.frac)
}
func (k *clock) advance(d time.Duration) { k.t = k.t.Add(d) }

func newTest(rate int, frac float64) (*Controller, *clock) {
	k := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), frac: frac}
	c := New(rate)
	c.SetClock(k.now, k.rand)
	return c, k
}

func TestNil(t *testing.T) {
	var c *Controller
	if !c.Busy(time.Second).IsZero() || c.Delay() != 0 || c.Counter() != 0 {
		t.Fatal("nil controller limits")
	}
	c.Sent()
}

func TestFirstBusyCounts(t *testing.T) {
	c, k := newTest(0, 0)
	end := c.Busy(100 * time.Millisecond)
	if c.Counter() != 1 {
		t.Fatalf("N = %d after the first busy, want 1", c.Counter())
	}
	if want := k.t.Add(100 * time.Millisecond); !end.Equal(want) {
		t.Fatalf("pause end %v, want %v", end, want)
	}
	if len(k.asked) != 1 || k.asked[0] != RandomStep {
		t.Fatalf("random extension asked for %v, want [0, 1 × 50 ms]", k.asked)
	}
	if d := c.Delay(); d != 100*time.Millisecond {
		t.Fatalf("delay %v", d)
	}
}

func TestBusyWithinGapNotCounted(t *testing.T) {
	c, k := newTest(0, 0)
	c.Busy(50 * time.Millisecond)
	for range 5 { // a burst of copies 10 ms apart counts once
		k.advance(BusyGap)
		c.Busy(50 * time.Millisecond)
	}
	if n := c.Counter(); n != 1 {
		t.Fatalf("N = %d after copies ≤ 10 ms apart, want 1", n)
	}
	k.advance(BusyGap + time.Millisecond)
	c.Busy(50 * time.Millisecond)
	if n := c.Counter(); n != 2 {
		t.Fatalf("N = %d after a busy 11 ms later, want 2", n)
	}
}

func TestWaitIncludesRandomExtension(t *testing.T) {
	c, k := newTest(0, 1) // the random source returns its maximum
	start := k.t
	c.Busy(100 * time.Millisecond) // N = 1
	k.advance(20 * time.Millisecond)
	c.Busy(100 * time.Millisecond) // N = 2
	k.advance(20 * time.Millisecond)
	end := c.Busy(100 * time.Millisecond) // N = 3: wait 100 ms + up to 150 ms
	if got := k.asked; len(got) != 3 || got[0] != 50*time.Millisecond || got[1] != 100*time.Millisecond || got[2] != 150*time.Millisecond {
		t.Fatalf("random limits %v, want N × 50 ms", got)
	}
	if want := start.Add(40*time.Millisecond + 250*time.Millisecond); !end.Equal(want) {
		t.Fatalf("pause end %v, want %v", end.Sub(start), want.Sub(start))
	}
	// A shorter busy does not shorten the pause.
	k.advance(time.Millisecond)
	if e := c.Busy(0); !e.Equal(end) {
		t.Fatalf("pause shortened to %v", e.Sub(start))
	}
	// Half of the range.
	h, hk := newTest(0, 0.5)
	if e := h.Busy(10 * time.Millisecond); e.Sub(hk.t) != 35*time.Millisecond {
		t.Fatalf("wait %v, want 10 ms + 25 ms", e.Sub(hk.t))
	}
}

func TestDecay(t *testing.T) {
	c, k := newTest(0, 0)
	c.Busy(100 * time.Millisecond)
	k.advance(20 * time.Millisecond)
	c.Busy(100 * time.Millisecond)
	k.advance(20 * time.Millisecond)
	end := c.Busy(100 * time.Millisecond) // N = 3, pause ends 100 ms from now
	k.t = end.Add(-time.Millisecond)
	if n := c.Counter(); n != 3 {
		t.Fatalf("N = %d during the pause", n)
	}
	// The slow duration: N × 100 ms after the pause.
	k.t = end.Add(3*SlowStep - time.Nanosecond)
	if n := c.Counter(); n != 3 {
		t.Fatalf("N = %d during the slow duration", n)
	}
	for want := 2; want >= 0; want-- {
		k.t = end.Add(3*SlowStep + time.Duration(2-want)*DecayStep)
		if n := c.Counter(); n != want {
			t.Fatalf("N = %d at %v after the pause, want %d", n, k.t.Sub(end), want)
		}
	}
	k.advance(time.Hour)
	if n := c.Counter(); n != 0 {
		t.Fatalf("N = %d after an hour", n)
	}
	// A new busy after the decay starts from the decayed counter and
	// counts, however long ago the previous one was.
	c.Busy(0)
	if n := c.Counter(); n != 1 {
		t.Fatalf("N = %d", n)
	}
	// One during the decay continues from where it is.
	d, dk := newTest(0, 0)
	d.Busy(0)
	dk.advance(20 * time.Millisecond)
	d.Busy(0)
	dk.advance(20 * time.Millisecond)
	d.Busy(0) // N = 3, pause ended now
	dk.advance(3*SlowStep + DecayStep)
	if n := d.Counter(); n != 1 {
		t.Fatalf("N = %d", n)
	}
	d.Busy(0)
	if n := d.Counter(); n != 2 {
		t.Fatalf("N = %d after a busy during the decay, want 2", n)
	}
}

func TestMinimumGap(t *testing.T) {
	c, k := newTest(50, 0)
	if d := c.Delay(); d != 0 {
		t.Fatalf("first send delayed by %v", d)
	}
	c.Sent()
	if d := c.Delay(); d != 20*time.Millisecond {
		t.Fatalf("gap %v, want 20 ms at 50/s", d)
	}
	k.advance(15 * time.Millisecond)
	if d := c.Delay(); d != 5*time.Millisecond {
		t.Fatalf("gap %v", d)
	}
	k.advance(5 * time.Millisecond)
	if d := c.Delay(); d != 0 {
		t.Fatalf("gap %v after 20 ms", d)
	}
	// No rate: no gap.
	u, _ := newTest(0, 0)
	u.Sent()
	if d := u.Delay(); d != 0 {
		t.Fatalf("unlimited gap %v", d)
	}
}

func TestReducedRateAfterBusy(t *testing.T) {
	c, k := newTest(50, 0)
	end := c.Busy(40 * time.Millisecond) // N = 1
	if d := c.Delay(); d != 40*time.Millisecond {
		t.Fatalf("delay %v, want the wait time", d)
	}
	k.t = end
	if d := c.Delay(); d != 0 {
		t.Fatalf("delay %v at the end of the pause", d)
	}
	c.Sent()
	if d := c.Delay(); d != 40*time.Millisecond {
		t.Fatalf("gap %v while N = 1, want 2 × 20 ms", d)
	}
	// Once N is 0 the normal gap applies again.
	k.t = end.Add(SlowStep + DecayStep)
	c.Sent()
	if d := c.Delay(); d != 20*time.Millisecond {
		t.Fatalf("gap %v after the decay", d)
	}
	// Without a rate the unit is one TP1 telegram time.
	u, uk := newTest(0, 0)
	uk.t = u.Busy(0)
	u.Sent()
	if d := u.Delay(); d != 2*TelegramTime {
		t.Fatalf("gap %v while N = 1 without a rate", d)
	}
}

func TestCryptoRand(t *testing.T) {
	if cryptoRand(0) != 0 || cryptoRand(-1) != 0 {
		t.Fatal("non-zero for an empty range")
	}
	for range 100 {
		if d := cryptoRand(50 * time.Millisecond); d < 0 || d > 50*time.Millisecond {
			t.Fatalf("out of range: %v", d)
		}
	}
}
