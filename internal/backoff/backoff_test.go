// SPDX-License-Identifier: MIT

package backoff

import (
	"testing"
	"testing/synctest"
	"time"
)

// The pauses of a loop that keeps failing: Min, doubling, at most Max.
// The clock is the bubble's, so the pauses are exact.
func TestLoopPauses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var l Loop
		want := []time.Duration{
			5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond,
			80 * time.Millisecond, 160 * time.Millisecond, 320 * time.Millisecond, 640 * time.Millisecond,
			time.Second, time.Second, time.Second,
		}
		for i, w := range want {
			start := time.Now()
			if !l.Wait(nil) {
				t.Fatalf("failure %d: the pause ended early", i+1)
			}
			if d := time.Since(start); d != w {
				t.Errorf("failure %d: paused %v, want %v", i+1, d, w)
			}
		}
		l.Reset()
		if d := l.Next(); d != Min {
			t.Errorf("after a success: %v, want %v", d, Min)
		}
	})
}

// A failure long after the previous pause is a first failure again; one
// within Max of its end continues the series.
func TestLoopFailuresFarApart(t *testing.T) {
	for _, tc := range []struct {
		gap  time.Duration // after the end of the second pause, of 10 ms
		want time.Duration
	}{
		{0, 20 * time.Millisecond},
		{Max - time.Nanosecond, 20 * time.Millisecond},
		{Max, 20 * time.Millisecond},
		{Max + time.Nanosecond, Min},
		{time.Hour, Min},
	} {
		synctest.Test(t, func(t *testing.T) {
			var l Loop
			l.Wait(nil)
			l.Wait(nil)
			time.Sleep(tc.gap)
			if d := l.Next(); d != tc.want {
				t.Errorf("a failure %v after the previous pause: pause %v, want %v", tc.gap, d, tc.want)
			}
		})
	}
}

// The longest pause repeats while failures follow each other, also when
// each comes a little after its pause ended, as on a real clock.
func TestLoopStaysAtMax(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var l Loop
		for l.Next() < Max {
			time.Sleep(l.pause)
		}
		for i := range 5 {
			time.Sleep(Max + 3*time.Millisecond)
			if d := l.Next(); d != Max {
				t.Fatalf("pause %d after the longest: %v, want %v", i+1, d, Max)
			}
		}
	})
}

func TestLoopWaitEndsOnDone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var l Loop
		done := make(chan struct{})
		close(done)
		start := time.Now()
		if l.Wait(done) {
			t.Error("Wait reported a whole pause although done is closed")
		}
		if d := time.Since(start); d != 0 {
			t.Errorf("Wait took %v with done closed", d)
		}
		// Closed during the pause.
		done = make(chan struct{})
		go func() {
			time.Sleep(time.Millisecond)
			close(done)
		}()
		start = time.Now()
		if l.Wait(done) {
			t.Error("Wait reported a whole pause although done was closed during it")
		}
		if d := time.Since(start); d != time.Millisecond {
			t.Errorf("Wait returned after %v, want 1ms", d)
		}
	})
}

func TestJitter(t *testing.T) {
	low := func(int64) int64 { return 0 }
	high := func(n int64) int64 { return n }
	for _, tc := range []struct {
		d        time.Duration
		min, max time.Duration
	}{
		{-time.Second, 0, 0},
		{0, 0, 0},
		{1, 0, 1},
		{2, 1, 2},
		{3, 1, 3},
		{time.Second, 500 * time.Millisecond, time.Second},
		{30 * time.Second, 15 * time.Second, 30 * time.Second},
		{1<<63 - 1, (1<<63 - 1) / 2, 1<<63 - 1},
	} {
		if got := Jitter(tc.d, low); got != tc.min {
			t.Errorf("Jitter(%v) with the lowest random value = %v, want %v", tc.d, got, tc.min)
		}
		if got := Jitter(tc.d, high); got != tc.max {
			t.Errorf("Jitter(%v) with the highest random value = %v, want %v", tc.d, got, tc.max)
		}
		for range 64 {
			if got := Jitter(tc.d, nil); got < tc.min || got > tc.max {
				t.Fatalf("Jitter(%v) = %v, outside [%v, %v]", tc.d, got, tc.min, tc.max)
			}
		}
	}
	if uniform(0) != 0 || uniform(-1) != 0 {
		t.Error("uniform of an empty range is not 0")
	}
}

// Two endpoints with the same backoff do not wait the same times.
func TestJitterDiffers(t *testing.T) {
	const n = 32
	same := 0
	for range n {
		one, other := Jitter(time.Second, nil), Jitter(time.Second, nil)
		if one == other {
			same++
		}
	}
	if same == n {
		t.Fatalf("%d pairs of pauses were equal", n)
	}
}
