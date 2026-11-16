// SPDX-License-Identifier: MIT

package routing

import "time"

// SetFlowClock replaces the clock of the flow control and gives the pause
// no random extension.
func (c *Conn) SetFlowClock(now func() time.Time) {
	c.flow.SetClock(now, func(time.Duration) time.Duration { return 0 })
}

// BusyCount returns the busy counter of the flow control.
func (c *Conn) BusyCount() int { return c.flow.Counter() }
