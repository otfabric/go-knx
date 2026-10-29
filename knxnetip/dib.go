// SPDX-License-Identifier: MIT

package knxnetip

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"

	"github.com/otfabric/go-knx"
)

// DIBType is the description type code of a DIB.
type DIBType uint8

// Description type codes.
const (
	DIBDeviceInfo         DIBType = 0x01
	DIBSupportedServices  DIBType = 0x02
	DIBIPConfig           DIBType = 0x03
	DIBIPCurrentConfig    DIBType = 0x04
	DIBKNXAddresses       DIBType = 0x05
	DIBSecuredServices    DIBType = 0x06
	DIBTunnellingInfo     DIBType = 0x07
	DIBExtendedDeviceInfo DIBType = 0x08
	DIBManufacturerData   DIBType = 0xFE
)

// String names the description type.
func (t DIBType) String() string {
	switch t {
	case DIBDeviceInfo:
		return "DEVICE_INFO"
	case DIBSupportedServices:
		return "SUPP_SVC_FAMILIES"
	case DIBIPConfig:
		return "IP_CONFIG"
	case DIBIPCurrentConfig:
		return "IP_CUR_CONFIG"
	case DIBKNXAddresses:
		return "KNX_ADDRESSES"
	case DIBSecuredServices:
		return "SECURED_SERVICE_FAMILIES"
	case DIBTunnellingInfo:
		return "TUNNELLING_INFO"
	case DIBExtendedDeviceInfo:
		return "EXTENDED_DEVICE_INFO"
	case DIBManufacturerData:
		return "MFR_DATA"
	default:
		return fmt.Sprintf("0x%02X", uint8(t))
	}
}

// DIB is a description information block.
type DIB interface {
	// Type returns the description type code.
	Type() DIBType
	// AppendTo appends the encoded block, length and type octets included.
	AppendTo(b []byte) []byte
}

// Medium is a KNX medium code.
type Medium uint8

// KNX medium codes.
const (
	MediumTP1   Medium = 0x02
	MediumPL110 Medium = 0x04
	MediumRF    Medium = 0x10
	MediumIP    Medium = 0x20
)

// String names the medium.
func (m Medium) String() string {
	switch m {
	case MediumTP1:
		return "TP1"
	case MediumPL110:
		return "PL110"
	case MediumRF:
		return "RF"
	case MediumIP:
		return "KNX IP"
	default:
		return fmt.Sprintf("0x%02X", uint8(m))
	}
}

// DeviceInfoLen is the length of a DEVICE_INFO DIB.
const DeviceInfoLen = 54

// DeviceInfo is the DEVICE_INFO DIB: the identity of a KNXnet/IP device.
type DeviceInfo struct {
	Medium Medium
	// Status is the device status; bit 0 is the programming mode.
	Status uint8
	// Address is the KNX individual address of the device.
	Address knx.IndividualAddress
	// ProjectInstallation is the project-installation identifier.
	ProjectInstallation uint16
	// Serial is the KNX serial number (manufacturer code in the first two
	// octets).
	Serial [6]byte
	// Multicast is the routing multicast address (0.0.0.0 if none).
	Multicast netip.Addr
	// MAC is the Ethernet MAC address.
	MAC [6]byte
	// Name is the friendly name, at most 30 ISO 8859-1 octets.
	Name string
}

// Type returns DIBDeviceInfo.
func (DeviceInfo) Type() DIBType { return DIBDeviceInfo }

// ProgrammingMode reports bit 0 of the device status.
func (d DeviceInfo) ProgrammingMode() bool { return d.Status&0x01 != 0 }

// SerialString returns the serial number as "0000:00000000" hex
// (manufacturer:number).
func (d DeviceInfo) SerialString() string {
	return fmt.Sprintf("%02X%02X:%02X%02X%02X%02X", d.Serial[0], d.Serial[1], d.Serial[2], d.Serial[3], d.Serial[4], d.Serial[5])
}

// AppendTo appends the encoded block. A name longer than 30 octets is cut.
func (d DeviceInfo) AppendTo(b []byte) []byte {
	b = append(b, DeviceInfoLen, byte(DIBDeviceInfo), byte(d.Medium), d.Status)
	b = binary.BigEndian.AppendUint16(b, uint16(d.Address))
	b = binary.BigEndian.AppendUint16(b, d.ProjectInstallation)
	b = append(b, d.Serial[:]...)
	m := [4]byte{}
	if a := d.Multicast.Unmap(); a.Is4() {
		m = a.As4()
	}
	b = append(b, m[:]...)
	b = append(b, d.MAC[:]...)
	var name [30]byte
	copy(name[:], latin1(d.Name))
	return append(b, name[:]...)
}

func parseDeviceInfo(p []byte) (DeviceInfo, error) {
	if len(p) != DeviceInfoLen {
		return DeviceInfo{}, malformed("DEVICE_INFO: length %d, want %d", len(p), DeviceInfoLen)
	}
	d := DeviceInfo{
		Medium:              Medium(p[2]),
		Status:              p[3],
		Address:             knx.IndividualAddress(binary.BigEndian.Uint16(p[4:])),
		ProjectInstallation: binary.BigEndian.Uint16(p[6:]),
		Multicast:           netip.AddrFrom4([4]byte{p[14], p[15], p[16], p[17]}),
	}
	copy(d.Serial[:], p[8:14])
	copy(d.MAC[:], p[18:24])
	name := p[24:54]
	if i := bytes.IndexByte(name, 0); i >= 0 {
		name = name[:i]
	}
	d.Name = fromLatin1(name)
	return d, nil
}

// ServiceFamilyID identifies a KNXnet/IP service family.
type ServiceFamilyID uint8

// Service families.
const (
	FamilyCore             ServiceFamilyID = 0x02
	FamilyDeviceManagement ServiceFamilyID = 0x03
	FamilyTunnelling       ServiceFamilyID = 0x04
	FamilyRouting          ServiceFamilyID = 0x05
	FamilyRemoteLogging    ServiceFamilyID = 0x06
	FamilyRemoteConfig     ServiceFamilyID = 0x07
	FamilyObjectServer     ServiceFamilyID = 0x08
	FamilySecurity         ServiceFamilyID = 0x09
)

// String names the family.
func (f ServiceFamilyID) String() string {
	switch f {
	case FamilyCore:
		return "Core"
	case FamilyDeviceManagement:
		return "DeviceManagement"
	case FamilyTunnelling:
		return "Tunnelling"
	case FamilyRouting:
		return "Routing"
	case FamilyRemoteLogging:
		return "RemoteLogging"
	case FamilyRemoteConfig:
		return "RemoteConfigurationAndDiagnosis"
	case FamilyObjectServer:
		return "ObjectServer"
	case FamilySecurity:
		return "Security"
	default:
		return fmt.Sprintf("0x%02X", uint8(f))
	}
}

// ServiceFamily is a family and its version.
type ServiceFamily struct {
	ID      ServiceFamilyID
	Version uint8
}

// ServiceFamilies is the SUPP_SVC_FAMILIES DIB or, with Secured set, the
// SECURED_SERVICE_FAMILIES DIB.
type ServiceFamilies struct {
	Secured  bool
	Families []ServiceFamily
}

// Type returns DIBSupportedServices or DIBSecuredServices.
func (s ServiceFamilies) Type() DIBType {
	if s.Secured {
		return DIBSecuredServices
	}
	return DIBSupportedServices
}

// Version returns the version of family id, and false if it is absent.
func (s ServiceFamilies) Version(id ServiceFamilyID) (uint8, bool) {
	for _, f := range s.Families {
		if f.ID == id {
			return f.Version, true
		}
	}
	return 0, false
}

// AppendTo appends the encoded block.
func (s ServiceFamilies) AppendTo(b []byte) []byte {
	b = append(b, byte(2+2*len(s.Families)), byte(s.Type()))
	for _, f := range s.Families {
		b = append(b, byte(f.ID), f.Version)
	}
	return b
}

func parseFamilies(p []byte, secured bool) (ServiceFamilies, error) {
	if len(p)%2 != 0 {
		return ServiceFamilies{}, malformed("%s: odd length %d", DIBType(p[1]), len(p))
	}
	s := ServiceFamilies{Secured: secured, Families: make([]ServiceFamily, 0, (len(p)-2)/2)}
	for i := 2; i < len(p); i += 2 {
		s.Families = append(s.Families, ServiceFamily{ID: ServiceFamilyID(p[i]), Version: p[i+1]})
	}
	return s, nil
}

// IPConfig is the IP_CONFIG DIB.
type IPConfig struct {
	IP, Mask, Gateway netip.Addr
	// Capabilities: bit 0 BootP, bit 1 DHCP, bit 2 AutoIP.
	Capabilities uint8
	// Assignment: bit 0 manual, bit 1 BootP, bit 2 DHCP, bit 3 AutoIP.
	Assignment uint8
}

// Type returns DIBIPConfig.
func (IPConfig) Type() DIBType { return DIBIPConfig }

// AppendTo appends the encoded block.
func (c IPConfig) AppendTo(b []byte) []byte {
	b = append(b, 16, byte(DIBIPConfig))
	b = appendIP4(b, c.IP)
	b = appendIP4(b, c.Mask)
	b = appendIP4(b, c.Gateway)
	return append(b, c.Capabilities, c.Assignment)
}

// IPCurrentConfig is the IP_CUR_CONFIG DIB.
type IPCurrentConfig struct {
	IP, Mask, Gateway, DHCPServer netip.Addr
	Assignment                    uint8
}

// Type returns DIBIPCurrentConfig.
func (IPCurrentConfig) Type() DIBType { return DIBIPCurrentConfig }

// AppendTo appends the encoded block.
func (c IPCurrentConfig) AppendTo(b []byte) []byte {
	b = append(b, 20, byte(DIBIPCurrentConfig))
	b = appendIP4(b, c.IP)
	b = appendIP4(b, c.Mask)
	b = appendIP4(b, c.Gateway)
	b = appendIP4(b, c.DHCPServer)
	return append(b, c.Assignment, 0)
}

// KNXAddresses is the KNX_ADDRESSES DIB: the individual address of the
// device followed by its additional (tunnelling) addresses.
type KNXAddresses struct {
	Addresses []knx.IndividualAddress
}

// Type returns DIBKNXAddresses.
func (KNXAddresses) Type() DIBType { return DIBKNXAddresses }

// AppendTo appends the encoded block.
func (k KNXAddresses) AppendTo(b []byte) []byte {
	b = append(b, byte(2+2*len(k.Addresses)), byte(DIBKNXAddresses))
	for _, a := range k.Addresses {
		b = binary.BigEndian.AppendUint16(b, uint16(a))
	}
	return b
}

// TunnelSlot is a tunnelling address of a TUNNELLING_INFO DIB.
type TunnelSlot struct {
	Address knx.IndividualAddress
	// Status: bit 0 free, bit 1 authorised, bit 2 usable.
	Status uint16
}

// Free reports whether the slot is free.
func (s TunnelSlot) Free() bool { return s.Status&0x01 != 0 }

// TunnellingInfo is the TUNNELLING_INFO DIB.
type TunnellingInfo struct {
	MaxAPDU uint16
	Slots   []TunnelSlot
}

// Type returns DIBTunnellingInfo.
func (TunnellingInfo) Type() DIBType { return DIBTunnellingInfo }

// AppendTo appends the encoded block.
func (t TunnellingInfo) AppendTo(b []byte) []byte {
	b = append(b, byte(4+4*len(t.Slots)), byte(DIBTunnellingInfo))
	b = binary.BigEndian.AppendUint16(b, t.MaxAPDU)
	for _, s := range t.Slots {
		b = binary.BigEndian.AppendUint16(b, uint16(s.Address))
		b = binary.BigEndian.AppendUint16(b, s.Status)
	}
	return b
}

// ExtendedDeviceInfo is the EXTENDED_DEVICE_INFO DIB.
type ExtendedDeviceInfo struct {
	MediumStatus     uint8
	MaxAPDU          uint16
	DeviceDescriptor uint16
}

// Type returns DIBExtendedDeviceInfo.
func (ExtendedDeviceInfo) Type() DIBType { return DIBExtendedDeviceInfo }

// AppendTo appends the encoded block.
func (e ExtendedDeviceInfo) AppendTo(b []byte) []byte {
	b = append(b, 8, byte(DIBExtendedDeviceInfo), e.MediumStatus, 0)
	b = binary.BigEndian.AppendUint16(b, e.MaxAPDU)
	return binary.BigEndian.AppendUint16(b, e.DeviceDescriptor)
}

// ManufacturerData is the MFR_DATA DIB.
type ManufacturerData struct {
	Manufacturer uint16
	Data         []byte
}

// Type returns DIBManufacturerData.
func (ManufacturerData) Type() DIBType { return DIBManufacturerData }

// AppendTo appends the encoded block.
func (m ManufacturerData) AppendTo(b []byte) []byte {
	b = append(b, byte(4+len(m.Data)), byte(DIBManufacturerData))
	b = binary.BigEndian.AppendUint16(b, m.Manufacturer)
	return append(b, m.Data...)
}

// UnknownDIB keeps a DIB of a type this package does not decode.
type UnknownDIB struct {
	DIBType DIBType
	Data    []byte
}

// Type returns the type code.
func (u UnknownDIB) Type() DIBType { return u.DIBType }

// AppendTo appends the encoded block.
func (u UnknownDIB) AppendTo(b []byte) []byte {
	b = append(b, byte(2+len(u.Data)), byte(u.DIBType))
	return append(b, u.Data...)
}

// ParseDIB decodes one DIB at the start of b and returns the remaining
// octets.
func ParseDIB(b []byte) (DIB, []byte, error) {
	if len(b) < 2 {
		return nil, nil, malformed("DIB: %d octets", len(b))
	}
	n := int(b[0])
	if n < 2 || n > len(b) {
		return nil, nil, malformed("DIB length %d with %d octets left", n, len(b))
	}
	p, rest := b[:n], b[n:]
	var d DIB
	var err error
	switch DIBType(p[1]) {
	case DIBDeviceInfo:
		d, err = parseDeviceInfo(p)
	case DIBSupportedServices:
		d, err = parseFamilies(p, false)
	case DIBSecuredServices:
		d, err = parseFamilies(p, true)
	case DIBIPConfig:
		if n != 16 {
			return nil, nil, malformed("IP_CONFIG: length %d, want 16", n)
		}
		d = IPConfig{IP: ip4(p[2:]), Mask: ip4(p[6:]), Gateway: ip4(p[10:]), Capabilities: p[14], Assignment: p[15]}
	case DIBIPCurrentConfig:
		if n != 20 {
			return nil, nil, malformed("IP_CUR_CONFIG: length %d, want 20", n)
		}
		d = IPCurrentConfig{IP: ip4(p[2:]), Mask: ip4(p[6:]), Gateway: ip4(p[10:]), DHCPServer: ip4(p[14:]), Assignment: p[18]}
	case DIBKNXAddresses:
		if n%2 != 0 || n < 4 {
			return nil, nil, malformed("KNX_ADDRESSES: length %d", n)
		}
		k := KNXAddresses{}
		for i := 2; i < n; i += 2 {
			k.Addresses = append(k.Addresses, knx.IndividualAddress(binary.BigEndian.Uint16(p[i:])))
		}
		d = k
	case DIBTunnellingInfo:
		if n < 4 || (n-4)%4 != 0 {
			return nil, nil, malformed("TUNNELLING_INFO: length %d", n)
		}
		t := TunnellingInfo{MaxAPDU: binary.BigEndian.Uint16(p[2:])}
		for i := 4; i < n; i += 4 {
			t.Slots = append(t.Slots, TunnelSlot{Address: knx.IndividualAddress(binary.BigEndian.Uint16(p[i:])), Status: binary.BigEndian.Uint16(p[i+2:])})
		}
		d = t
	case DIBExtendedDeviceInfo:
		if n != 8 {
			return nil, nil, malformed("EXTENDED_DEVICE_INFO: length %d, want 8", n)
		}
		d = ExtendedDeviceInfo{MediumStatus: p[2], MaxAPDU: binary.BigEndian.Uint16(p[4:]), DeviceDescriptor: binary.BigEndian.Uint16(p[6:])}
	case DIBManufacturerData:
		if n < 4 {
			return nil, nil, malformed("MFR_DATA: length %d", n)
		}
		d = ManufacturerData{Manufacturer: binary.BigEndian.Uint16(p[2:]), Data: clone(p[4:])}
	default:
		d = UnknownDIB{DIBType: DIBType(p[1]), Data: clone(p[2:])}
	}
	if err != nil {
		return nil, nil, err
	}
	return d, rest, nil
}

// DIBs is a sequence of description information blocks.
type DIBs []DIB

// AppendTo appends every block.
func (ds DIBs) AppendTo(b []byte) []byte {
	for _, d := range ds {
		b = d.AppendTo(b)
	}
	return b
}

// ParseDIBs decodes blocks until b is empty.
func ParseDIBs(b []byte) (DIBs, error) {
	var ds DIBs
	for len(b) > 0 {
		d, rest, err := ParseDIB(b)
		if err != nil {
			return nil, err
		}
		ds = append(ds, d)
		b = rest
	}
	return ds, nil
}

// DeviceInfo returns the DEVICE_INFO block.
func (ds DIBs) DeviceInfo() (DeviceInfo, bool) {
	for _, d := range ds {
		if v, ok := d.(DeviceInfo); ok {
			return v, true
		}
	}
	return DeviceInfo{}, false
}

// SupportedServices returns the SUPP_SVC_FAMILIES block.
func (ds DIBs) SupportedServices() (ServiceFamilies, bool) {
	for _, d := range ds {
		if v, ok := d.(ServiceFamilies); ok && !v.Secured {
			return v, true
		}
	}
	return ServiceFamilies{}, false
}

// SecuredServices returns the SECURED_SERVICE_FAMILIES block.
func (ds DIBs) SecuredServices() (ServiceFamilies, bool) {
	for _, d := range ds {
		if v, ok := d.(ServiceFamilies); ok && v.Secured {
			return v, true
		}
	}
	return ServiceFamilies{}, false
}

// Find returns the first block of type t.
func (ds DIBs) Find(t DIBType) (DIB, bool) {
	for _, d := range ds {
		if d.Type() == t {
			return d, true
		}
	}
	return nil, false
}

func ip4(b []byte) netip.Addr { return netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]}) }

func appendIP4(b []byte, a netip.Addr) []byte {
	v := [4]byte{}
	if a = a.Unmap(); a.Is4() {
		v = a.As4()
	}
	return append(b, v[:]...)
}

func clone(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return append([]byte(nil), b...)
}

// latin1 encodes s as ISO 8859-1; runes outside it become '?'.
func latin1(s string) []byte {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if r > 0xFF {
			r = '?'
		}
		out = append(out, byte(r))
	}
	return out
}

func fromLatin1(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		sb.WriteRune(rune(c))
	}
	return sb.String()
}
