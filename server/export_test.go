// SPDX-License-Identifier: MIT

package server

import "time"

// TimerSynchronized is closed when the timer synchronisation of secure
// routing has ended: its window has passed, or the server closed.
func (s *Server) TimerSynchronized() <-chan struct{} { return s.rsynced }

// SetFlowClock replaces the clock of the routing flow control and gives
// the pause no random extension.
func (s *Server) SetFlowClock(now func() time.Time) {
	s.flow.SetClock(now, func(time.Duration) time.Duration { return 0 })
}

// BusyCount returns the busy counter of the routing flow control.
func (s *Server) BusyCount() int { return s.flow.Counter() }
