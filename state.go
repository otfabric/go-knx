// SPDX-License-Identifier: MIT

package knx

import "fmt"

// State is the state of a connection.
type State int

// Connection states.
const (
	StateDisconnected State = iota
	StateConnecting
	StateConnected
	StateReconnecting
	StateClosed
)

// String names the state.
func (s State) String() string {
	switch s {
	case StateDisconnected:
		return "disconnected"
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateReconnecting:
		return "reconnecting"
	case StateClosed:
		return "closed"
	default:
		return fmt.Sprintf("State(%d)", int(s))
	}
}
