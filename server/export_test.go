// SPDX-License-Identifier: MIT

package server

// TimerSynchronized is closed when the timer synchronisation of secure
// routing has ended: its window has passed, or the server closed.
func (s *Server) TimerSynchronized() <-chan struct{} { return s.rsynced }
