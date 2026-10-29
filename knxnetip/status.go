// SPDX-License-Identifier: MIT

package knxnetip

import (
	"errors"
	"fmt"

	"github.com/otfabric/go-knx"
)

// Status is a KNXnet/IP status (error) code of a response or
// acknowledgement.
type Status uint8

// Status codes.
const (
	StatusNoError             Status = 0x00 // E_NO_ERROR
	StatusHostProtocolType    Status = 0x01 // E_HOST_PROTOCOL_TYPE
	StatusVersionNotSupported Status = 0x02 // E_VERSION_NOT_SUPPORTED
	StatusSequenceNumber      Status = 0x04 // E_SEQUENCE_NUMBER
	StatusGenericError        Status = 0x0F // E_ERROR (tunnelling feature services)
	StatusConnectionID        Status = 0x21 // E_CONNECTION_ID
	StatusConnectionType      Status = 0x22 // E_CONNECTION_TYPE
	StatusConnectionOption    Status = 0x23 // E_CONNECTION_OPTION
	StatusNoMoreConnections   Status = 0x24 // E_NO_MORE_CONNECTIONS
	StatusNoMoreUniqueConns   Status = 0x25 // E_NO_MORE_UNIQUE_CONNECTIONS
	StatusDataConnection      Status = 0x26 // E_DATA_CONNECTION
	StatusKNXConnection       Status = 0x27 // E_KNX_CONNECTION
	StatusAuthorisationError  Status = 0x28 // E_AUTHORISATION_ERROR (tunnelling v2)
	StatusTunnellingLayer     Status = 0x29 // E_TUNNELLING_LAYER
	StatusNoTunnellingAddress Status = 0x2D // E_NO_TUNNELLING_ADDRESS (tunnelling v2)
	StatusConnectionInUse     Status = 0x2E // E_CONNECTION_IN_USE (tunnelling v2)
)

var statusNames = map[Status]string{
	StatusNoError:             "E_NO_ERROR",
	StatusHostProtocolType:    "E_HOST_PROTOCOL_TYPE",
	StatusVersionNotSupported: "E_VERSION_NOT_SUPPORTED",
	StatusSequenceNumber:      "E_SEQUENCE_NUMBER",
	StatusGenericError:        "E_ERROR",
	StatusConnectionID:        "E_CONNECTION_ID",
	StatusConnectionType:      "E_CONNECTION_TYPE",
	StatusConnectionOption:    "E_CONNECTION_OPTION",
	StatusNoMoreConnections:   "E_NO_MORE_CONNECTIONS",
	StatusNoMoreUniqueConns:   "E_NO_MORE_UNIQUE_CONNECTIONS",
	StatusDataConnection:      "E_DATA_CONNECTION",
	StatusKNXConnection:       "E_KNX_CONNECTION",
	StatusAuthorisationError:  "E_AUTHORISATION_ERROR",
	StatusTunnellingLayer:     "E_TUNNELLING_LAYER",
	StatusNoTunnellingAddress: "E_NO_TUNNELLING_ADDRESS",
	StatusConnectionInUse:     "E_CONNECTION_IN_USE",
}

// String returns the name of the status code, such as
// "E_NO_MORE_CONNECTIONS", or "0x%02X" for an unknown one.
func (s Status) String() string {
	if n, ok := statusNames[s]; ok {
		return n
	}
	return fmt.Sprintf("0x%02X", uint8(s))
}

// StatusError is a response or acknowledgement with a status other than
// E_NO_ERROR. It matches [knx.ErrRejected] with errors.Is, and
// [knx.ErrBusy] for E_NO_MORE_CONNECTIONS and E_NO_MORE_UNIQUE_CONNECTIONS.
type StatusError struct {
	Service ServiceType
	Status  Status
}

// Error describes the failure, for example
// "knxnetip: CONNECT_RESPONSE: E_NO_MORE_CONNECTIONS (0x24)".
func (e *StatusError) Error() string {
	return fmt.Sprintf("knxnetip: %s: %s (0x%02X)", e.Service, e.Status, uint8(e.Status))
}

// Is matches knx.ErrRejected and, for exhausted connections, knx.ErrBusy.
func (e *StatusError) Is(target error) bool {
	if target == knx.ErrRejected {
		return true
	}
	return target == knx.ErrBusy && (e.Status == StatusNoMoreConnections || e.Status == StatusNoMoreUniqueConns)
}

// StatusOf returns the status of a *StatusError in err's chain.
func StatusOf(err error) (Status, bool) {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Status, true
	}
	return 0, false
}
