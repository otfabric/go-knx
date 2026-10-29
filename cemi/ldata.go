// SPDX-License-Identifier: MIT

package cemi

import (
	"encoding/binary"
	"fmt"

	"github.com/otfabric/go-knx"
)

// Control field 1 bits.
const (
	// Ctrl1Standard is the frame type bit: set for a standard frame,
	// clear for an extended frame.
	Ctrl1Standard byte = 0x80
	// Ctrl1NoRepeat set means "do not repeat on error".
	Ctrl1NoRepeat byte = 0x20
	// Ctrl1Broadcast set means a normal broadcast, clear a system
	// broadcast.
	Ctrl1Broadcast byte = 0x10
	// Ctrl1AckRequest asks for a layer-2 acknowledgement.
	Ctrl1AckRequest byte = 0x02
	// Ctrl1ConfirmError marks an L_Data.con that reports an error.
	Ctrl1ConfirmError byte = 0x01
)

// Control field 2 bits.
const (
	// Ctrl2GroupAddress marks a group destination address.
	Ctrl2GroupAddress byte = 0x80
)

// Default control fields: a standard frame, not repeated, broadcast, low
// priority; a group destination with hop count 6. These are the fields
// KNXnet/IP clients usually send in an L_Data.req.
const (
	DefaultCtrl1 = Ctrl1Standard | Ctrl1NoRepeat | Ctrl1Broadcast | byte(knx.PriorityLow)<<2
	DefaultCtrl2 = Ctrl2GroupAddress | 6<<4
)

// MaxStandardNPDU is the longest NPDU (TPDU length minus one) of a
// standard frame; longer TPDUs need an extended frame.
const MaxStandardNPDU = 15

// LData is an L_Data.req, L_Data.ind or L_Data.con frame. The control
// fields are kept as sent; the accessors interpret them.
type LData struct {
	MsgCode MessageCode
	AddInfo []AdditionalInfo
	Ctrl1   byte
	Ctrl2   byte
	Source  knx.IndividualAddress
	// Destination is a group address when Ctrl2GroupAddress is set,
	// otherwise an individual address. Use [LData.Group] and
	// [LData.Individual].
	Destination uint16
	// TPDU is the transport protocol data unit: the TPCI octet, the APCI
	// and the data (package apdu).
	TPDU []byte
}

// NewGroupFrame returns an L_Data frame of code to group address dst with
// the default control fields and priority p.
func NewGroupFrame(code MessageCode, src knx.IndividualAddress, dst knx.GroupAddress, p knx.Priority, tpdu []byte) *LData {
	f := &LData{MsgCode: code, Ctrl1: DefaultCtrl1, Ctrl2: DefaultCtrl2, Source: src, Destination: uint16(dst), TPDU: tpdu}
	f.SetPriority(p)
	if len(tpdu)-1 > MaxStandardNPDU {
		f.Ctrl1 &^= Ctrl1Standard
	}
	return f
}

// NewIndividualFrame returns an L_Data frame of code to individual address
// dst with the default control fields and priority p.
func NewIndividualFrame(code MessageCode, src, dst knx.IndividualAddress, p knx.Priority, tpdu []byte) *LData {
	f := NewGroupFrame(code, src, knx.GroupAddress(dst), p, tpdu)
	f.Ctrl2 &^= Ctrl2GroupAddress
	return f
}

// Code returns the message code.
func (f *LData) Code() MessageCode { return f.MsgCode }

// Standard reports a standard frame (frame type bit set).
func (f *LData) Standard() bool { return f.Ctrl1&Ctrl1Standard != 0 }

// Repeat reports whether the frame may be repeated on error.
func (f *LData) Repeat() bool { return f.Ctrl1&Ctrl1NoRepeat == 0 }

// SystemBroadcast reports a system broadcast (broadcast bit clear).
func (f *LData) SystemBroadcast() bool { return f.Ctrl1&Ctrl1Broadcast == 0 }

// Priority returns the telegram priority.
func (f *LData) Priority() knx.Priority { return knx.Priority(f.Ctrl1>>2) & 0x03 }

// SetPriority sets the telegram priority.
func (f *LData) SetPriority(p knx.Priority) { f.Ctrl1 = f.Ctrl1&^0x0C | byte(p&0x03)<<2 }

// AckRequested reports the acknowledge request bit.
func (f *LData) AckRequested() bool { return f.Ctrl1&Ctrl1AckRequest != 0 }

// ConfirmError reports an L_Data.con that signals an error.
func (f *LData) ConfirmError() bool { return f.Ctrl1&Ctrl1ConfirmError != 0 }

// IsGroup reports a group destination address.
func (f *LData) IsGroup() bool { return f.Ctrl2&Ctrl2GroupAddress != 0 }

// Group returns the destination as a group address; ok is false for an
// individual destination.
func (f *LData) Group() (knx.GroupAddress, bool) { return knx.GroupAddress(f.Destination), f.IsGroup() }

// Individual returns the destination as an individual address; ok is
// false for a group destination.
func (f *LData) Individual() (knx.IndividualAddress, bool) {
	return knx.IndividualAddress(f.Destination), !f.IsGroup()
}

// HopCount returns the hop count (0..7).
func (f *LData) HopCount() uint8 { return f.Ctrl2 >> 4 & 0x07 }

// SetHopCount sets the hop count (0..7).
func (f *LData) SetHopCount(n uint8) { f.Ctrl2 = f.Ctrl2&^0x70 | (n&0x07)<<4 }

// ExtendedFormat returns the extended frame format (low nibble of control
// field 2): 0 for standard addressing, 01xx for LTE-HEE.
func (f *LData) ExtendedFormat() uint8 { return f.Ctrl2 & 0x0F }

// DestinationString returns the destination in its presentation: "1/2/3"
// or "1.1.10".
func (f *LData) DestinationString() string {
	if f.IsGroup() {
		return knx.GroupAddress(f.Destination).String()
	}
	return knx.IndividualAddress(f.Destination).String()
}

// Clone returns a deep copy.
func (f *LData) Clone() *LData {
	c := *f
	c.TPDU = clone(f.TPDU)
	if f.AddInfo != nil {
		c.AddInfo = make([]AdditionalInfo, len(f.AddInfo))
		for i, a := range f.AddInfo {
			c.AddInfo[i] = AdditionalInfo{Type: a.Type, Data: clone(a.Data)}
		}
	}
	return &c
}

// String summarises the frame, for example
// "L_Data.ind 1.1.10 -> 1/2/3 low hop 6 tpdu 0081".
func (f *LData) String() string {
	return fmt.Sprintf("%s %s -> %s %s hop %d tpdu %X", f.MsgCode, f.Source, f.DestinationString(), f.Priority(), f.HopCount(), f.TPDU)
}

// AppendTo appends the encoded frame. A standard frame must carry an NPDU
// of at most 15 octets; the TPDU must hold 1..255 octets of NPDU plus the
// TPCI octet.
func (f *LData) AppendTo(b []byte) ([]byte, error) {
	if len(f.TPDU) < 1 || len(f.TPDU) > 256 {
		return nil, fmt.Errorf("%w: cemi: TPDU of %d octets", knx.ErrInvalidValue, len(f.TPDU))
	}
	if f.Standard() && len(f.TPDU)-1 > MaxStandardNPDU {
		return nil, fmt.Errorf("%w: cemi: standard frame with an NPDU of %d octets (at most %d)", knx.ErrInvalidValue, len(f.TPDU)-1, MaxStandardNPDU)
	}
	b, err := appendAddInfo(append(b, byte(f.MsgCode)), f.AddInfo)
	if err != nil {
		return nil, err
	}
	b = append(b, f.Ctrl1, f.Ctrl2)
	b = binary.BigEndian.AppendUint16(b, uint16(f.Source))
	b = binary.BigEndian.AppendUint16(b, f.Destination)
	b = append(b, byte(len(f.TPDU)-1))
	return append(b, f.TPDU...), nil
}

func parseLData(b []byte) (Frame, error) {
	infos, rest, err := parseAddInfo(b)
	if err != nil {
		return nil, err
	}
	if len(rest) < 7 {
		return nil, malformed("%s: %d octets after the additional information, want at least 7", MessageCode(b[0]), len(rest))
	}
	n := int(rest[6])
	if len(rest) != 7+n+1 {
		return nil, malformed("%s: NPDU length %d, %d octets of TPDU", MessageCode(b[0]), n, len(rest)-7)
	}
	return &LData{
		MsgCode:     MessageCode(b[0]),
		AddInfo:     infos,
		Ctrl1:       rest[0],
		Ctrl2:       rest[1],
		Source:      knx.IndividualAddress(binary.BigEndian.Uint16(rest[2:])),
		Destination: binary.BigEndian.Uint16(rest[4:]),
		TPDU:        clone(rest[7:]),
	}, nil
}
