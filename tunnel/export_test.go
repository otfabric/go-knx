// SPDX-License-Identifier: MIT

package tunnel

// WithJitterSource sets the random source of the reconnect waits: f
// returns a value in [0, n].
func WithJitterSource(f func(n int64) int64) Option {
	return func(o *options) error { o.jitter = f; return nil }
}

// Closing returns the channel Close closes when it begins.
func Closing(c *Conn) <-chan struct{} { return c.stopping }
