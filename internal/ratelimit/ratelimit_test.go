// SPDX-License-Identifier: MIT

package ratelimit

import (
	"sync"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTest(rate int) (*Bucket, *clock) {
	c := &clock{t: time.Unix(1000, 0)}
	b := New(rate)
	b.now = c.now
	return b, c
}

func TestUnlimited(t *testing.T) {
	var nilBucket *Bucket
	if !nilBucket.Allow() {
		t.Fatal("nil bucket refused")
	}
	for _, r := range []int{0, -1} {
		b := New(r)
		if b != nil {
			t.Fatalf("New(%d) = %v, want nil", r, b)
		}
		for i := 0; i < 1000; i++ {
			if !b.Allow() {
				t.Fatalf("rate %d refused", r)
			}
		}
	}
}

func TestBurstThenRefill(t *testing.T) {
	b, c := newTest(10)
	for i := 0; i < 10; i++ {
		if !b.Allow() {
			t.Fatalf("burst token %d refused", i)
		}
	}
	if b.Allow() {
		t.Fatal("11th token allowed without time passing")
	}
	c.advance(50 * time.Millisecond) // half a token
	if b.Allow() {
		t.Fatal("allowed after half a token")
	}
	c.advance(50 * time.Millisecond) // one token in total
	if !b.Allow() {
		t.Fatal("refused after one token's time")
	}
	if b.Allow() {
		t.Fatal("second token allowed")
	}
	// A long pause refills up to the burst, not beyond.
	c.advance(time.Hour)
	n := 0
	for b.Allow() {
		n++
	}
	if n != 10 {
		t.Fatalf("%d tokens after a long pause, want 10", n)
	}
}

func TestSteadyRate(t *testing.T) {
	b, c := newTest(50)
	for b.Allow() {
	}
	allowed := 0
	for i := 0; i < 1000; i++ { // 1 s in 1 ms steps
		c.advance(time.Millisecond)
		if b.Allow() {
			allowed++
		}
	}
	if allowed < 49 || allowed > 51 {
		t.Fatalf("%d allowed in one second at 50/s", allowed)
	}
}

func TestClockBackwards(t *testing.T) {
	b, c := newTest(1)
	if !b.Allow() {
		t.Fatal("first refused")
	}
	c.advance(-time.Second)
	if b.Allow() {
		t.Fatal("allowed after the clock went back")
	}
}

func TestConcurrent(t *testing.T) {
	b := New(100)
	var wg sync.WaitGroup
	var mu sync.Mutex
	n := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if b.Allow() {
					mu.Lock()
					n++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if n < 100 || n > 110 {
		t.Fatalf("%d allowed from a burst of 100", n)
	}
}
