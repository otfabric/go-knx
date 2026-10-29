// SPDX-License-Identifier: MIT

// Package ratelimit is a token bucket.
package ratelimit

import (
	"sync"
	"time"
)

// Bucket allows rate events per second with a burst of rate events. A
// nil *Bucket or a rate of 0 allows everything.
type Bucket struct {
	mu     sync.Mutex
	rate   float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

// New returns a bucket of rate events per second (0: unlimited).
func New(rate int) *Bucket {
	if rate <= 0 {
		return nil
	}
	return &Bucket{rate: float64(rate), tokens: float64(rate), now: time.Now}
}

// Allow takes a token and reports whether one was available.
func (b *Bucket) Allow() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if !b.last.IsZero() {
		b.tokens += now.Sub(b.last).Seconds() * b.rate
		if b.tokens > b.rate {
			b.tokens = b.rate
		}
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
