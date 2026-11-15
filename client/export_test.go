// SPDX-License-Identifier: MIT

package client

import "time"

// MaxPendingAnswers is the bound of the queue of answers to individually
// addressed secured requests.
const MaxPendingAnswers = maxPendingAnswers

// AnswersDropped returns the number of answers that found the queue full.
func (c *Client) AnswersDropped() uint64 { return c.answersDropped.Load() }

// PendingReads returns the number of group reads waiting for a response.
func (c *Client) PendingReads() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.waiters)
}

// SetAckTimeout shortens the transport acknowledgement timeout for a test.
func SetAckTimeout(d time.Duration) (restore func()) {
	old := ackTimeout
	ackTimeout = d
	return func() { ackTimeout = old }
}
