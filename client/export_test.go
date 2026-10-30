// SPDX-License-Identifier: MIT

package client

import "time"

// SetAckTimeout shortens the transport acknowledgement timeout for a test.
func SetAckTimeout(d time.Duration) (restore func()) {
	old := ackTimeout
	ackTimeout = d
	return func() { ackTimeout = old }
}
