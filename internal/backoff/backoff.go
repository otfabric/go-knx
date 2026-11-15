// SPDX-License-Identifier: MIT

// Package backoff spaces the retries of a loop whose operation failed (an
// accept or a read on a socket), so that an error that persists does not
// turn the loop into a busy loop, and spreads the retries of a
// reconnection.
package backoff

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

// Pauses of a [Loop].
const (
	// Min is the pause after the first failure.
	Min = 5 * time.Millisecond
	// Max is the longest pause. A failure more than Max after the end
	// of the previous pause counts as a first failure again.
	Max = time.Second
)

// Loop is the state of one retrying loop. The zero value is ready to
// use; a Loop belongs to the goroutine that runs the loop.
type Loop struct {
	pause time.Duration
	until time.Time // end of the pause of the previous failure
}

// Next records a failure and returns the pause before the next attempt:
// Min after a first failure, twice the previous pause after each further
// one, at most Max.
func (l *Loop) Next() time.Duration {
	now := time.Now()
	switch {
	case l.pause == 0 || now.Sub(l.until) > Max:
		l.pause = Min
	case l.pause < Max:
		l.pause = min(2*l.pause, Max)
	}
	l.until = now.Add(l.pause)
	return l.pause
}

// Reset records a success: the next failure is a first failure.
func (l *Loop) Reset() { l.pause = 0 }

// Wait records a failure and pauses as long as Next says. It returns
// false, at once, when done is closed before the pause is over; a nil
// done never ends a pause early.
func (l *Loop) Wait(done <-chan struct{}) bool {
	t := time.NewTimer(l.Next())
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-done:
		return false
	}
}

// Jitter returns a pause for the backoff d of a reconnection, uniformly
// distributed in [d/2, d] (equal jitter): the endpoints that lost the
// same peer at the same moment do not all come back at once. rnd returns
// a uniform value in [0, n] for n >= 0; nil uses crypto/rand.
func Jitter(d time.Duration, rnd func(n int64) int64) time.Duration {
	if d <= 0 {
		return 0
	}
	if rnd == nil {
		rnd = uniform
	}
	half := d / 2
	return half + time.Duration(rnd(int64(d-half)))
}

// uniform returns a value in [0, n] from crypto/rand.
func uniform(n int64) int64 {
	if n <= 0 {
		return 0
	}
	var b [8]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read does not fail (Go 1.24+)
	return int64(binary.BigEndian.Uint64(b[:]) % (uint64(n) + 1))
}
