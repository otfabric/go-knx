// SPDX-License-Identifier: MIT

package cemi

import (
	"encoding/binary"
	"fmt"

	"github.com/otfabric/go-knx"
)

// TP1Frame returns the KNX TP1 standard data frame of an L_Data frame, as
// carried in an L_Busmon.ind: control field, source, destination, address
// type / hop count / length octet, TPDU and check octet. Only standard
// frames (NPDU of at most 15 octets) have this format.
func TP1Frame(f *LData) ([]byte, error) {
	if len(f.TPDU) < 1 || len(f.TPDU)-1 > MaxStandardNPDU {
		return nil, fmt.Errorf("%w: cemi: a TP1 standard frame carries an NPDU of at most %d octets, not %d", knx.ErrUnsupported, MaxStandardNPDU, len(f.TPDU)-1)
	}
	// Control field: standard frame (bit 7), not repeated (bit 5), the
	// fixed bit 4, priority (bits 3-2).
	b := []byte{0x80 | 0x20 | 0x10 | byte(f.Priority())<<2}
	b = binary.BigEndian.AppendUint16(b, uint16(f.Source))
	b = binary.BigEndian.AppendUint16(b, f.Destination)
	o := f.HopCount()<<4 | byte(len(f.TPDU)-1)
	if f.IsGroup() {
		o |= 0x80
	}
	b = append(b, o)
	b = append(b, f.TPDU...)
	var x byte
	for _, c := range b {
		x ^= c
	}
	return append(b, ^x), nil
}

// ParseTP1 decodes a TP1 standard data frame (as in an L_Busmon.ind) into
// an L_Data.ind. It checks the frame type, the length and the check
// octet.
func ParseTP1(b []byte) (*LData, error) {
	if len(b) < 8 {
		return nil, malformed("TP1 frame of %d octets", len(b))
	}
	if b[0]&0xD3 != 0x90 {
		return nil, fmt.Errorf("%w: cemi: TP1 control field 0x%02X is not a standard data frame", knx.ErrUnsupported, b[0])
	}
	n := int(b[5] & 0x0F)
	if len(b) != 6+n+1+1 {
		return nil, malformed("TP1 frame: length %d, %d octets", n, len(b))
	}
	var x byte
	for _, c := range b[:len(b)-1] {
		x ^= c
	}
	if ^x != b[len(b)-1] {
		return nil, malformed("TP1 frame: check octet 0x%02X, want 0x%02X", b[len(b)-1], ^x)
	}
	f := &LData{
		MsgCode:     LDataInd,
		Ctrl1:       Ctrl1Standard | Ctrl1Broadcast | b[0]&0x0C | Ctrl1NoRepeat,
		Source:      knx.IndividualAddress(binary.BigEndian.Uint16(b[1:])),
		Destination: binary.BigEndian.Uint16(b[3:]),
		TPDU:        clone(b[6 : 6+n+1]),
	}
	if b[0]&0x20 == 0 {
		f.Ctrl1 &^= Ctrl1NoRepeat // a repeated frame
	}
	f.Ctrl2 = b[5] & 0x70
	if b[5]&0x80 != 0 {
		f.Ctrl2 |= Ctrl2GroupAddress
	}
	return f, nil
}
