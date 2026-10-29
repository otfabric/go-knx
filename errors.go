// SPDX-License-Identifier: MIT

package knx

import "errors"

// Sentinel errors shared by every package. They are usually wrapped with
// detail; test with errors.Is.
var (
	// ErrInvalidAddress reports an individual or group address that is out
	// of range or not in one of the accepted presentations.
	ErrInvalidAddress = errors.New("knx: invalid address")

	// ErrMalformed reports a frame that cannot be decoded: too short, a
	// length field that disagrees with the data, a structure of the wrong
	// size or type. Decoders never panic on malformed input.
	ErrMalformed = errors.New("knx: malformed frame")

	// ErrUnsupported reports a service, connection type, frame or
	// datapoint type that is not implemented, or that the peer does not
	// support.
	ErrUnsupported = errors.New("knx: unsupported")

	// ErrInvalidOption reports an option or argument a function cannot be
	// called with.
	ErrInvalidOption = errors.New("knx: invalid option")

	// ErrInvalidValue reports a datapoint value outside the range of its
	// type, or data of the wrong size for it.
	ErrInvalidValue = errors.New("knx: invalid value")

	// ErrClosed reports an operation on a connection, client or server
	// that was closed.
	ErrClosed = errors.New("knx: closed")

	// ErrTimeout reports a request that the peer did not answer in time.
	ErrTimeout = errors.New("knx: timeout")

	// ErrConnectionLost reports that the peer ended the connection or
	// stopped answering heartbeats.
	ErrConnectionLost = errors.New("knx: connection lost")

	// ErrRejected reports a request the peer refused with a KNXnet/IP
	// status code; a *knxnetip.StatusError carries it.
	ErrRejected = errors.New("knx: rejected")

	// ErrBusy reports that a limit was reached: a full queue, no free
	// tunnelling channel, a routing busy indication.
	ErrBusy = errors.New("knx: busy")

	// ErrNotConfirmed reports a tunnelled telegram whose L_Data.con
	// reported an error, or did not arrive.
	ErrNotConfirmed = errors.New("knx: not confirmed")

	// ErrSecurity reports a KNX IP Secure or KNX Data Secure failure: an
	// authentication tag that does not verify, a replayed sequence number,
	// a missing key. Secure connections never fall back to plain ones.
	ErrSecurity = errors.New("knx: security failure")
)
