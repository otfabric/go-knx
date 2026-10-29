// SPDX-License-Identifier: MIT

// Package devmgmt is a KNXnet/IP device management client: it reads and
// writes the interface object properties of a KNXnet/IP server (local
// device management with M_PropRead and M_PropWrite) over a device
// management connection.
//
//	c, err := devmgmt.Dial(ctx, "192.168.1.10")
//	name, err := c.PropRead(ctx, devmgmt.ObjectKNXnetIPParameter, 1, devmgmt.PIDFriendlyName, 1, 30)
package devmgmt

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/tunnel"
)

// Interface object types.
const (
	ObjectDevice            uint16 = 0x0000
	ObjectRouter            uint16 = 0x0006
	ObjectKNXnetIPParameter uint16 = 0x000B
)

// Property identifiers of the device, router and KNXnet/IP parameter
// objects.
const (
	PIDObjectType                uint8 = 1
	PIDSerialNumber              uint8 = 11
	PIDManufacturerID            uint8 = 12
	PIDMediumStatus              uint8 = 51 // router object
	PIDProgMode                  uint8 = 54 // device object
	PIDMaxAPDULength             uint8 = 56 // device object
	PIDIOList                    uint8 = 71 // device object
	PIDDeviceDescriptor          uint8 = 83
	PIDProjectInstallationID     uint8 = 51 // KNXnet/IP parameter object
	PIDKNXIndividualAddress      uint8 = 52
	PIDAdditionalIndividualAddrs uint8 = 53
	PIDIPAssignmentMethod        uint8 = 55
	PIDCurrentIPAddress          uint8 = 57
	PIDCurrentSubnetMask         uint8 = 58
	PIDCurrentDefaultGateway     uint8 = 59
	PIDMACAddress                uint8 = 64
	PIDSystemSetupMulticast      uint8 = 65
	PIDRoutingMulticast          uint8 = 66
	PIDFriendlyName              uint8 = 76
)

// PropertyError is a negative confirmation: the server refused the
// access with a cEMI error code.
type PropertyError struct {
	ObjectType uint16
	PropertyID uint8
	Code       uint8
}

var errorNames = map[uint8]string{
	0x00: "unspecified error", 0x01: "out of range", 0x02: "out of max range", 0x03: "out of min range",
	0x04: "memory error", 0x05: "read only", 0x06: "illegal command", 0x07: "void DP (no such property)",
	0x08: "type conflict", 0x09: "property index range error", 0x0A: "value temporarily not writeable",
}

// Error describes the failure.
func (e *PropertyError) Error() string {
	n := errorNames[e.Code]
	if n == "" {
		n = "error"
	}
	return fmt.Sprintf("devmgmt: object 0x%04X property %d: %s (0x%02X)", e.ObjectType, e.PropertyID, n, e.Code)
}

// Is matches knx.ErrRejected.
func (e *PropertyError) Is(target error) bool { return target == knx.ErrRejected }

// Conn is a device management connection.
type Conn struct {
	t *tunnel.Conn
}

// Dial opens a device management connection to the server at addr.
// Options are those of package tunnel (WithTCP, WithNAT, timeouts...).
func Dial(ctx context.Context, addr string, opts ...tunnel.Option) (*Conn, error) {
	t, err := tunnel.Dial(ctx, addr, append(opts, tunnel.WithDeviceManagement())...)
	if err != nil {
		return nil, err
	}
	return &Conn{t: t}, nil
}

// Close closes the connection.
func (c *Conn) Close() error { return c.t.Close() }

// Tunnel returns the underlying connection.
func (c *Conn) Tunnel() *tunnel.Conn { return c.t }

// PropRead reads count elements (1..15) of a property from element start
// (1-based; start 0 reads the number of elements) and returns their
// octets.
func (c *Conn) PropRead(ctx context.Context, objType uint16, instance, pid uint8, start uint16, count uint8) ([]byte, error) {
	req := &cemi.Property{MsgCode: cemi.MPropReadReq, ObjectType: objType, Instance: instance, PropertyID: pid, Count: count, Start: start}
	con, err := c.roundTrip(ctx, req, cemi.MPropReadCon)
	if err != nil {
		return nil, err
	}
	if con.Count == 0 {
		code := uint8(0)
		if len(con.Data) > 0 {
			code = con.Data[0]
		}
		return nil, &PropertyError{ObjectType: objType, PropertyID: pid, Code: code}
	}
	return con.Data, nil
}

// PropElements returns the number of elements of a property.
func (c *Conn) PropElements(ctx context.Context, objType uint16, instance, pid uint8) (int, error) {
	b, err := c.PropRead(ctx, objType, instance, pid, 0, 1)
	if err != nil {
		return 0, err
	}
	if len(b) != 2 {
		return 0, fmt.Errorf("%w: devmgmt: element count of %d octets", knx.ErrMalformed, len(b))
	}
	return int(binary.BigEndian.Uint16(b)), nil
}

// PropWrite writes count elements of a property from element start.
func (c *Conn) PropWrite(ctx context.Context, objType uint16, instance, pid uint8, start uint16, count uint8, data []byte) error {
	req := &cemi.Property{MsgCode: cemi.MPropWriteReq, ObjectType: objType, Instance: instance, PropertyID: pid, Count: count, Start: start, Data: data}
	con, err := c.roundTrip(ctx, req, cemi.MPropWriteCon)
	if err != nil {
		return err
	}
	if con.Count == 0 || len(con.Data) > 0 {
		code := uint8(0)
		if len(con.Data) > 0 {
			code = con.Data[0]
		}
		return &PropertyError{ObjectType: objType, PropertyID: pid, Code: code}
	}
	return nil
}

func (c *Conn) roundTrip(ctx context.Context, req *cemi.Property, want cemi.MessageCode) (*cemi.Property, error) {
	if err := c.t.Send(ctx, req); err != nil {
		return nil, err
	}
	for {
		f, err := c.t.Receive(ctx)
		if err != nil {
			return nil, err
		}
		con, ok := f.(*cemi.Property)
		if !ok || con.MsgCode != want || con.ObjectType != req.ObjectType || con.Instance != req.Instance ||
			con.PropertyID != req.PropertyID || con.Start != req.Start {
			continue
		}
		return con, nil
	}
}
