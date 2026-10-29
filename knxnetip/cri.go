// SPDX-License-Identifier: MIT

package knxnetip

import (
	"encoding/binary"
	"fmt"

	"github.com/otfabric/go-knx"
)

// ConnectionType is the connection type code of a CRI or CRD.
type ConnectionType uint8

// Connection types.
const (
	DeviceManagementConnection ConnectionType = 0x03
	TunnelConnection           ConnectionType = 0x04
	RemoteLoggingConnection    ConnectionType = 0x06
	RemoteConfigConnection     ConnectionType = 0x07
	ObjectServerConnection     ConnectionType = 0x08
)

// String names the connection type.
func (t ConnectionType) String() string {
	switch t {
	case DeviceManagementConnection:
		return "DEVICE_MGMT_CONNECTION"
	case TunnelConnection:
		return "TUNNEL_CONNECTION"
	case RemoteLoggingConnection:
		return "REMLOG_CONNECTION"
	case RemoteConfigConnection:
		return "REMCONF_CONNECTION"
	case ObjectServerConnection:
		return "OBJSVR_CONNECTION"
	default:
		return fmt.Sprintf("0x%02X", uint8(t))
	}
}

// TunnelLayer is the KNX layer a tunnelling connection is made on.
type TunnelLayer uint8

// Tunnelling layers.
const (
	TunnelLinkLayer  TunnelLayer = 0x02
	TunnelRaw        TunnelLayer = 0x04
	TunnelBusmonitor TunnelLayer = 0x80
)

// String names the layer.
func (l TunnelLayer) String() string {
	switch l {
	case TunnelLinkLayer:
		return "TUNNEL_LINKLAYER"
	case TunnelRaw:
		return "TUNNEL_RAW"
	case TunnelBusmonitor:
		return "TUNNEL_BUSMONITOR"
	default:
		return fmt.Sprintf("0x%02X", uint8(l))
	}
}

// CRI is the connection request information of a CONNECT_REQUEST.
type CRI struct {
	Type ConnectionType
	// Layer is the tunnelling layer (tunnel connections).
	Layer TunnelLayer
	// Address requests a specific tunnelling individual address: the
	// extended CRI of tunnelling v2. Used when HasAddress is set.
	Address    knx.IndividualAddress
	HasAddress bool
	// Data is the host protocol independent data of other connection
	// types, kept as sent.
	Data []byte
}

// TunnelCRI returns the CRI of a tunnelling connection on layer.
func TunnelCRI(layer TunnelLayer) CRI { return CRI{Type: TunnelConnection, Layer: layer} }

// AppendTo appends the encoded CRI.
func (c CRI) AppendTo(b []byte) []byte {
	switch c.Type {
	case TunnelConnection:
		if c.HasAddress {
			b = append(b, 6, byte(c.Type), byte(c.Layer), 0)
			return binary.BigEndian.AppendUint16(b, uint16(c.Address))
		}
		return append(b, 4, byte(c.Type), byte(c.Layer), 0)
	default:
		b = append(b, byte(2+len(c.Data)), byte(c.Type))
		return append(b, c.Data...)
	}
}

// ParseCRI decodes a CRI that fills b.
func ParseCRI(b []byte) (CRI, error) {
	if len(b) < 2 || int(b[0]) != len(b) {
		return CRI{}, malformed("CRI: length octet %v for %d octets", first(b), len(b))
	}
	c := CRI{Type: ConnectionType(b[1])}
	switch c.Type {
	case TunnelConnection:
		switch len(b) {
		case 4:
		case 6:
			c.HasAddress = true
			c.Address = knx.IndividualAddress(binary.BigEndian.Uint16(b[4:]))
		default:
			return CRI{}, malformed("tunnel CRI: length %d, want 4 or 6", len(b))
		}
		c.Layer = TunnelLayer(b[2])
	case DeviceManagementConnection:
		if len(b) != 2 {
			return CRI{}, malformed("device management CRI: length %d, want 2", len(b))
		}
	default:
		c.Data = clone(b[2:])
	}
	return c, nil
}

// CRD is the connection response data block of a CONNECT_RESPONSE.
type CRD struct {
	Type ConnectionType
	// Address is the individual address assigned to a tunnelling
	// connection.
	Address knx.IndividualAddress
	// Data is the data of other connection types, kept as sent.
	Data []byte
}

// AppendTo appends the encoded CRD.
func (c CRD) AppendTo(b []byte) []byte {
	if c.Type == TunnelConnection {
		b = append(b, 4, byte(c.Type))
		return binary.BigEndian.AppendUint16(b, uint16(c.Address))
	}
	b = append(b, byte(2+len(c.Data)), byte(c.Type))
	return append(b, c.Data...)
}

// ParseCRD decodes a CRD that fills b.
func ParseCRD(b []byte) (CRD, error) {
	if len(b) < 2 || int(b[0]) != len(b) {
		return CRD{}, malformed("CRD: length octet %v for %d octets", first(b), len(b))
	}
	c := CRD{Type: ConnectionType(b[1])}
	switch c.Type {
	case TunnelConnection:
		if len(b) != 4 {
			return CRD{}, malformed("tunnel CRD: length %d, want 4", len(b))
		}
		c.Address = knx.IndividualAddress(binary.BigEndian.Uint16(b[2:]))
	case DeviceManagementConnection:
		if len(b) != 2 {
			return CRD{}, malformed("device management CRD: length %d, want 2", len(b))
		}
	default:
		c.Data = clone(b[2:])
	}
	return c, nil
}

func first(b []byte) any {
	if len(b) == 0 {
		return "none"
	}
	return b[0]
}
