// SPDX-License-Identifier: MIT

package server

import (
	"encoding/binary"
	"net/netip"
	"sync"

	"github.com/otfabric/go-knx/cemi"
)

// Server constants reported by device management and the tunnelling
// interface features.
const (
	// DeviceDescriptor is the device descriptor type 0 the server reports:
	// 0x091A, a KNXnet/IP router.
	DeviceDescriptor = 0x091A
	// MaxAPDU is the longest APDU the server passes (extended frames).
	MaxAPDU = 254
)

// Interface object types.
const (
	objDevice   = 0x0000
	objRouter   = 0x0006
	objKNXnetIP = 0x000B
)

// Property identifiers (the device object and the KNXnet/IP parameter
// object), cross-checked against Calimero's PropertyAccess and xknx's
// profile constants.
const (
	pidObjectType                = 1
	pidSerialNumber              = 11
	pidManufacturerID            = 12
	pidMediumStatus              = 51 // router object
	pidProgMode                  = 54 // device object
	pidMaxAPDULength             = 56 // device object
	pidDeviceDescriptor          = 83
	pidProjectInstallationID     = 51 // KNXnet/IP parameter object
	pidKNXIndividualAddress      = 52
	pidAdditionalIndividualAddrs = 53
	pidIPAssignmentMethod        = 55
	pidCurrentIPAddress          = 57
	pidCurrentSubnetMask         = 58
	pidCurrentDefaultGateway     = 59
	pidMACAddress                = 64
	pidSystemSetupMulticast      = 65
	pidRoutingMulticast          = 66
	pidFriendlyName              = 76
)

// cEMI management error codes of a negative confirmation.
const (
	errReadOnly   = 0x05
	errVoidDP     = 0x07 // the object or property does not exist
	errIndexRange = 0x09
)

// property is a read-only property: elements of size octets.
type property struct {
	size     int
	elements func() [][]byte
}

// propStore answers local device management (M_PropRead.req,
// M_PropWrite.req, M_Reset.req) for the server's interface objects. All
// properties are read only.
type propStore struct {
	s  *Server
	mu sync.Mutex
}

func u16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }

func ip4(a netip.Addr) []byte {
	if a = a.Unmap(); a.Is4() {
		v := a.As4()
		return v[:]
	}
	return []byte{0, 0, 0, 0}
}

func one(b []byte) func() [][]byte { return func() [][]byte { return [][]byte{b} } }

// properties returns the properties of interface object type t,
// instance 1.
func (p *propStore) properties(t uint16) map[uint8]property {
	s := p.s
	switch t {
	case objDevice:
		prog := byte(0)
		if s.o.progMode {
			prog = 1
		}
		return map[uint8]property{
			pidObjectType:       {2, one(u16(objDevice))},
			pidSerialNumber:     {6, one(s.o.serial[:])},
			pidManufacturerID:   {2, one(s.o.serial[:2])},
			pidProgMode:         {1, one([]byte{prog})},
			pidMaxAPDULength:    {2, one(u16(MaxAPDU))},
			pidDeviceDescriptor: {2, one(u16(DeviceDescriptor))},
		}
	case objRouter:
		return map[uint8]property{
			pidObjectType:   {2, one(u16(objRouter))},
			pidMediumStatus: {1, one([]byte{0})}, // connected
		}
	case objKNXnetIP:
		ip, mask := s.ifIP, netip.Addr{}
		routing := netip.IPv4Unspecified()
		if s.o.routing {
			routing = s.group.Addr()
		}
		name := make([]byte, 30)
		copy(name, s.o.name)
		names := func() [][]byte {
			out := make([][]byte, 30)
			for i := range out {
				out[i] = []byte{name[i]}
			}
			return out
		}
		addrs := func() [][]byte {
			out := make([][]byte, len(s.o.tunnels))
			for i, a := range s.o.tunnels {
				out[i] = u16(uint16(a))
			}
			return out
		}
		return map[uint8]property{
			pidObjectType:                {2, one(u16(objKNXnetIP))},
			pidProjectInstallationID:     {2, one(u16(0))},
			pidKNXIndividualAddress:      {2, one(u16(uint16(s.o.address)))},
			pidAdditionalIndividualAddrs: {2, addrs},
			pidIPAssignmentMethod:        {1, one([]byte{0x01})}, // manual
			pidCurrentIPAddress:          {4, one(ip4(ip))},
			pidCurrentSubnetMask:         {4, one(ip4(mask))},
			pidCurrentDefaultGateway:     {4, one(ip4(netip.Addr{}))},
			pidMACAddress:                {6, one(s.o.mac[:])},
			pidSystemSetupMulticast:      {4, one([]byte{224, 0, 23, 12})},
			pidRoutingMulticast:          {4, one(ip4(routing))},
			pidFriendlyName:              {1, names},
		}
	}
	return nil
}

// handle answers a local device management request; nil when there is
// no answer.
func (p *propStore) handle(f cemi.Frame) cemi.Frame {
	switch f := f.(type) {
	case *cemi.Property:
		switch f.MsgCode {
		case cemi.MPropReadReq:
			return p.read(f)
		case cemi.MPropWriteReq:
			return &cemi.Property{MsgCode: cemi.MPropWriteCon, ObjectType: f.ObjectType, Instance: f.Instance,
				PropertyID: f.PropertyID, Start: f.Start, Data: []byte{errReadOnly}}
		}
	case *cemi.FunctionProperty:
		if f.MsgCode == cemi.MFuncPropCommandReq || f.MsgCode == cemi.MFuncPropStateReadReq {
			// No function properties: a negative confirmation (no data).
			return &cemi.FunctionProperty{MsgCode: cemi.MFuncPropCon, ObjectType: f.ObjectType, Instance: f.Instance, PropertyID: f.PropertyID}
		}
	case *cemi.Reset:
		// The virtual server has nothing to restart.
		return nil
	}
	return nil
}

func (p *propStore) read(f *cemi.Property) cemi.Frame {
	neg := func(code byte) cemi.Frame {
		return &cemi.Property{MsgCode: cemi.MPropReadCon, ObjectType: f.ObjectType, Instance: f.Instance,
			PropertyID: f.PropertyID, Count: 0, Start: f.Start, Data: []byte{code}}
	}
	if f.Instance != 1 {
		return neg(errVoidDP)
	}
	props := p.properties(f.ObjectType)
	pr, ok := props[f.PropertyID]
	if !ok {
		return neg(errVoidDP)
	}
	elems := pr.elements()
	if f.Start == 0 {
		// Element 0 is the current number of elements.
		if f.Count != 1 {
			return neg(errIndexRange)
		}
		return &cemi.Property{MsgCode: cemi.MPropReadCon, ObjectType: f.ObjectType, Instance: f.Instance,
			PropertyID: f.PropertyID, Count: 1, Start: 0, Data: u16(uint16(len(elems)))}
	}
	first, n := int(f.Start)-1, int(f.Count)
	if n == 0 || first+n > len(elems) {
		return neg(errIndexRange)
	}
	var data []byte
	for _, e := range elems[first : first+n] {
		data = append(data, e...)
	}
	return &cemi.Property{MsgCode: cemi.MPropReadCon, ObjectType: f.ObjectType, Instance: f.Instance,
		PropertyID: f.PropertyID, Count: f.Count, Start: f.Start, Data: data}
}
