// SPDX-License-Identifier: MIT

// Package mgmt implements remote device management over the KNX network:
// the application layer services a tool sends to a device's individual
// address (A_PropertyValue_Read, _Write and _Response,
// A_PropertyDescription_Read and _Response, A_DeviceDescriptor_Read and
// _Response), connectionless or in a transport layer connection,
// optionally secured with the device's tool key (KNX Data Secure point
// to point, S-A_Data with tool access).
//
// [Responder] is the device side. The tool side is client.Device (package client), which
// runs over a client's tunnelling or routing link.
//
// The services and the transport layer follow public descriptions and
// xknx (MIT), and were checked against Calimero and xknx; this is
// interoperability, not conformance.
package mgmt

import (
	"encoding/binary"
	"fmt"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
)

// Interface object types (the IO list of the device object) used by the
// remote services.
const (
	ObjectDevice   uint16 = 0x0000
	ObjectSecurity uint16 = 0x0011
)

// Property identifiers of the security interface object, as commonly
// documented (not confirmed by a peer: tools set the security mode with
// function property services, which the responder does not implement).
const (
	PIDSecurityMode uint8 = 51
)

// Property is the header and data of A_PropertyValue_Read, _Write and
// _Response: the object is addressed by its index in the device's
// interface object list, not by its type.
type Property struct {
	Object uint8
	PID    uint8
	// Count is the number of elements (0..15); 0 in a response is a
	// negative response.
	Count uint8
	// Start is the first element (1-based; 0 is the element count).
	Start uint16
	Data  []byte
}

// TPDU returns the TPDU of service svc with this property header and
// data, numbered with tpci.
func (p Property) TPDU(tpci apdu.TPCI, svc apdu.APCI) []byte {
	d := make([]byte, 4, 4+len(p.Data))
	d[0], d[1] = p.Object, p.PID
	binary.BigEndian.PutUint16(d[2:], uint16(p.Count&0x0F)<<12|p.Start&0x0FFF)
	d = append(d, p.Data...)
	return apdu.TPDU{TPCI: tpci, APCI: svc, Data: d}.Bytes()
}

// ParseProperty decodes the data of a property value service.
func ParseProperty(t apdu.TPDU) (Property, error) {
	if len(t.Data) < 4 {
		return Property{}, fmt.Errorf("%w: mgmt: %s of %d octets", knx.ErrMalformed, t.APCI, len(t.Data))
	}
	v := binary.BigEndian.Uint16(t.Data[2:4])
	return Property{Object: t.Data[0], PID: t.Data[1], Count: uint8(v >> 12), Start: v & 0x0FFF, Data: append([]byte(nil), t.Data[4:]...)}, nil
}

// Description is a property description, the data of
// A_PropertyDescription_Response.
type Description struct {
	// Object is the index of the interface object. A [Describer] need
	// not set it: the [Responder] answers with the object of the request.
	Object uint8
	PID    uint8
	Index  uint8 // the property's index in its object
	// Type is the property datatype (6 bits on the wire); Writable is
	// the write enable bit.
	Type     PDT
	Writable bool
	// MaxElements is 12 bits on the wire (0..4095); a larger value is
	// sent as 4095. 0 in a response is a negative response: the device
	// has no such property.
	MaxElements uint16
	// Access is the read level (high nibble) and the write level (low).
	Access uint8
}

// descriptionLen is the length of the data of
// A_PropertyDescription_Response: object, PID, index, type, two octets of
// maximum elements, access.
const descriptionLen = 7

// ReadLevel returns the access level needed to read the property (0 is
// the highest privilege).
func (d Description) ReadLevel() uint8 { return d.Access >> 4 }

// WriteLevel returns the access level needed to write the property.
func (d Description) WriteLevel() uint8 { return d.Access & 0x0F }

// Data returns the 7 octets of A_PropertyDescription_Response: the type
// is masked to 6 bits, a maximum above 4095 is sent as 4095.
func (d Description) Data() []byte {
	typ := uint8(d.Type) & 0x3F
	if d.Writable {
		typ |= 0x80
	}
	b := []byte{d.Object, d.PID, d.Index, typ, 0, 0, d.Access}
	binary.BigEndian.PutUint16(b[4:6], min(d.MaxElements, 0x0FFF))
	return b
}

// TPDU returns A_PropertyDescription_Response with this description,
// numbered with tpci.
func (d Description) TPDU(tpci apdu.TPCI) []byte {
	return apdu.TPDU{TPCI: tpci, APCI: apdu.PropertyDescriptionResponseService, Data: d.Data()}.Bytes()
}

// ParseDescription decodes the data of A_PropertyDescription_Response.
// The reserved bits (bit 6 of the type, the upper 4 bits of the maximum
// element count) are ignored.
func ParseDescription(t apdu.TPDU) (Description, error) {
	if len(t.Data) != descriptionLen {
		return Description{}, fmt.Errorf("%w: mgmt: %s of %d octets, want %d", knx.ErrMalformed, t.APCI, len(t.Data), descriptionLen)
	}
	b := t.Data
	return Description{
		Object: b[0], PID: b[1], Index: b[2],
		Type: PDT(b[3] & 0x3F), Writable: b[3]&0x80 != 0,
		MaxElements: binary.BigEndian.Uint16(b[4:6]) & 0x0FFF,
		Access:      b[6],
	}, nil
}

// DescriptionReadTPDU returns A_PropertyDescription_Read of property pid
// of the object at index object; with pid 0 the property is named by
// its index in the object.
func DescriptionReadTPDU(tpci apdu.TPCI, object, pid, index uint8) []byte {
	return apdu.TPDU{TPCI: tpci, APCI: apdu.PropertyDescriptionReadService, Data: []byte{object, pid, index}}.Bytes()
}

// PropertyError is a negative A_PropertyValue_Response or
// A_PropertyDescription_Response: the device refused the access (no such
// object or property, out of range, read only...).
type PropertyError struct {
	Device knx.IndividualAddress
	Object uint8
	PID    uint8
}

// Error describes the failure.
func (e *PropertyError) Error() string {
	return fmt.Sprintf("mgmt: %s refused object %d property %d", e.Device, e.Object, e.PID)
}

// Is matches knx.ErrRejected.
func (e *PropertyError) Is(target error) bool { return target == knx.ErrRejected }

// DescriptorTPDU returns A_DeviceDescriptor_Read of descriptor type 0.
func DescriptorTPDU(tpci apdu.TPCI) []byte {
	return apdu.TPDU{TPCI: tpci, APCI: apdu.DeviceDescriptorReadService}.Bytes()
}
