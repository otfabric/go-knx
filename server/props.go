// SPDX-License-Identifier: MIT

package server

import (
	"encoding/binary"
	"net/netip"
	"slices"

	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/mgmt"
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
	objSecurity = 0x0011
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
	pidIOList                    = 71 // device object: the interface object types
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
	pidSecurityMode              = 51 // security object
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
// M_PropWrite.req, M_Reset.req) and, as mgmt.Properties, remote device
// management for the server's interface objects. The friendly name is
// writable; the other properties are read only.
type propStore struct {
	s *Server
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
			// The interface objects, by index: tools such as Calimero's
			// address objects by their index in this list.
			pidIOList: {2, func() [][]byte {
				var out [][]byte
				for _, t := range p.objects() {
					out = append(out, u16(t))
				}
				return out
			}},
		}
	case objSecurity:
		if s.o.toolKey == nil {
			return nil
		}
		return map[uint8]property{
			pidObjectType:   {2, one(u16(objSecurity))},
			pidSecurityMode: {1, one([]byte{1})},
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
		copy(name, s.friendlyName())
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
			con := &cemi.Property{MsgCode: cemi.MPropWriteCon, ObjectType: f.ObjectType, Instance: f.Instance,
				PropertyID: f.PropertyID, Start: f.Start, Count: f.Count}
			if f.Instance != 1 {
				con.Count, con.Data = 0, []byte{errVoidDP}
			} else if code := p.write(f.ObjectType, f.PropertyID, f.Start, f.Count, f.Data); code != 0 {
				con.Count, con.Data = 0, []byte{code}
			}
			return con
		default:
			// Confirmations and indications are not requests.
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
	if f.Instance != 1 {
		return &cemi.Property{MsgCode: cemi.MPropReadCon, ObjectType: f.ObjectType, Instance: f.Instance,
			PropertyID: f.PropertyID, Count: 0, Start: f.Start, Data: []byte{errVoidDP}}
	}
	data, code := p.readData(f.ObjectType, f.PropertyID, f.Start, f.Count)
	if code != 0 {
		return &cemi.Property{MsgCode: cemi.MPropReadCon, ObjectType: f.ObjectType, Instance: f.Instance,
			PropertyID: f.PropertyID, Count: 0, Start: f.Start, Data: []byte{code}}
	}
	return &cemi.Property{MsgCode: cemi.MPropReadCon, ObjectType: f.ObjectType, Instance: f.Instance,
		PropertyID: f.PropertyID, Count: f.Count, Start: f.Start, Data: data}
}

// readData returns count elements of a property of object type t from
// element start (0: the element count), or a cEMI error code.
func (p *propStore) readData(t uint16, pid uint8, start uint16, count uint8) ([]byte, byte) {
	pr, ok := p.properties(t)[pid]
	if !ok {
		return nil, errVoidDP
	}
	elems := pr.elements()
	if start == 0 {
		// Element 0 is the current number of elements.
		if count != 1 {
			return nil, errIndexRange
		}
		return u16(uint16(len(elems))), 0
	}
	first, n := int(start)-1, int(count)
	if n == 0 || first+n > len(elems) {
		return nil, errIndexRange
	}
	var data []byte
	for _, e := range elems[first : first+n] {
		data = append(data, e...)
	}
	return data, 0
}

// write writes count elements of a property from element start, or
// returns a cEMI error code. Only the friendly name is writable.
func (p *propStore) write(t uint16, pid uint8, start uint16, count uint8, data []byte) byte {
	pr, ok := p.properties(t)[pid]
	switch {
	case !ok:
		return errVoidDP
	case t != objKNXnetIP || pid != pidFriendlyName:
		return errReadOnly
	case start == 0 || count == 0 || int(start)-1+int(count) > len(pr.elements()) || len(data) != int(count):
		return errIndexRange
	}
	s := p.s
	s.nameMu.Lock()
	defer s.nameMu.Unlock()
	name := make([]byte, 30)
	copy(name, s.name)
	copy(name[start-1:], data)
	end := len(name)
	for end > 0 && name[end-1] == 0 {
		end--
	}
	s.name = string(name[:end])
	return 0
}

// objects returns the interface object types, by index.
func (p *propStore) objects() []uint16 {
	o := []uint16{objDevice, objRouter, objKNXnetIP}
	if p.s.o.toolKey != nil {
		o = append(o, objSecurity)
	}
	return o
}

// ReadProperty implements mgmt.Properties: objects by index.
func (p *propStore) ReadProperty(object, pid uint8, start uint16, count uint8) ([]byte, bool) {
	o := p.objects()
	if int(object) >= len(o) {
		return nil, false
	}
	data, code := p.readData(o[object], pid, start, count)
	return data, code == 0
}

// WriteProperty implements mgmt.Properties.
func (p *propStore) WriteProperty(object, pid uint8, start uint16, count uint8, data []byte) bool {
	o := p.objects()
	return int(object) < len(o) && p.write(o[object], pid, start, count, data) == 0
}

// Property datatypes (PDT) by element size: unsigned char, unsigned
// int, unsigned long, generic 6 octets.
var pdts = map[int]uint8{1: 0x02, 2: 0x04, 4: 0x09, 6: 0x16}

// DescribeProperty implements mgmt.Describer: the datatype follows the
// element size; the maximum is the current number of elements. Read
// access is free; only the friendly name is writable.
func (p *propStore) DescribeProperty(object, pid, index uint8) (mgmt.Description, bool) {
	o := p.objects()
	if int(object) >= len(o) {
		return mgmt.Description{}, false
	}
	props := p.properties(o[object])
	pids := make([]uint8, 0, len(props))
	for id := range props {
		pids = append(pids, id)
	}
	slices.Sort(pids)
	if pid == 0 {
		if int(index) >= len(pids) {
			return mgmt.Description{}, false
		}
		pid = pids[index]
	}
	pr, ok := props[pid]
	if !ok {
		return mgmt.Description{}, false
	}
	return mgmt.Description{
		PID: pid, Index: uint8(slices.Index(pids, pid)), Type: pdts[pr.size],
		Writable:    o[object] == objKNXnetIP && pid == pidFriendlyName,
		MaxElements: uint16(len(pr.elements())), Access: 0xF0,
	}, true
}
