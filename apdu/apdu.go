// SPDX-License-Identifier: MIT

// Package apdu decodes and encodes the transport layer control
// information (TPCI) and the application layer protocol data unit (APCI
// and data) carried in the TPDU of an L_Data frame.
//
// A TPDU starts with the TPCI octet; its two low bits are the high bits of
// the 10-bit APCI. Services with a 4-bit APCI (group values, memory and
// ADC access, device descriptors) carry a 6-bit parameter in the low bits
// of the second octet: the "small" value of A_GroupValue_Write and
// _Response, the octet count of A_Memory_Read. Services with a 10-bit APCI
// carry none.
package apdu

import (
	"fmt"

	"github.com/otfabric/go-knx"
)

// TKind is the kind of a transport layer PDU.
type TKind uint8

// Transport layer PDU kinds. Whether an unnumbered data PDU is
// T_Data_Group, T_Data_Broadcast or T_Data_Individual follows from the
// destination address of the frame, not from the TPCI.
const (
	// TData is an unnumbered data PDU (T_Data_Group, T_Data_Broadcast,
	// T_Data_Individual).
	TData TKind = iota
	// TDataTagGroup is T_Data_Tag_Group.
	TDataTagGroup
	// TDataConnected is a numbered data PDU of a transport connection.
	TDataConnected
	// TConnect is T_Connect.
	TConnect
	// TDisconnect is T_Disconnect.
	TDisconnect
	// TAck is T_ACK.
	TAck
	// TNak is T_NAK.
	TNak
)

// String names the kind.
func (k TKind) String() string {
	switch k {
	case TData:
		return "T_Data"
	case TDataTagGroup:
		return "T_Data_Tag_Group"
	case TDataConnected:
		return "T_Data_Connected"
	case TConnect:
		return "T_Connect"
	case TDisconnect:
		return "T_Disconnect"
	case TAck:
		return "T_ACK"
	case TNak:
		return "T_NAK"
	default:
		return fmt.Sprintf("TKind(%d)", uint8(k))
	}
}

// TPCI is the transport layer control information.
type TPCI struct {
	Kind TKind
	// Seq is the sequence number (0..15) of numbered PDUs.
	Seq uint8
}

// Octet returns the TPCI octet without the APCI bits.
func (t TPCI) Octet() byte {
	s := (t.Seq & 0x0F) << 2
	switch t.Kind {
	case TDataTagGroup:
		return 0x04
	case TDataConnected:
		return 0x40 | s
	case TConnect:
		return 0x80
	case TDisconnect:
		return 0x81
	case TAck:
		return 0xC2 | s
	case TNak:
		return 0xC3 | s
	default:
		return 0x00
	}
}

// IsControl reports a transport control PDU (connect, disconnect, ack,
// nak), which carries no APDU.
func (t TPCI) IsControl() bool { return t.Kind >= TConnect }

// ParseTPCI decodes the TPCI octet.
func ParseTPCI(b byte) (TPCI, error) {
	seq := b >> 2 & 0x0F
	switch {
	case b&0x80 == 0: // data
		if b&0x40 != 0 {
			return TPCI{Kind: TDataConnected, Seq: seq}, nil
		}
		switch b & 0x3C {
		case 0x00:
			return TPCI{Kind: TData}, nil
		case 0x04:
			return TPCI{Kind: TDataTagGroup}, nil
		}
	case b == 0x80:
		return TPCI{Kind: TConnect}, nil
	case b == 0x81:
		return TPCI{Kind: TDisconnect}, nil
	case b&0xC3 == 0xC2:
		return TPCI{Kind: TAck, Seq: seq}, nil
	case b&0xC3 == 0xC3:
		return TPCI{Kind: TNak, Seq: seq}, nil
	}
	return TPCI{}, fmt.Errorf("%w: apdu: TPCI octet 0x%02X", knx.ErrMalformed, b)
}

// TPDU is a decoded transport layer PDU.
type TPDU struct {
	TPCI TPCI
	// APCI is the application service (data PDUs only).
	APCI APCI
	// Short is the 6-bit parameter of a service with a 4-bit APCI.
	Short uint8
	// Data holds the octets after the APCI.
	Data []byte
}

// Parse decodes a TPDU. Control PDUs must be exactly one octet; data PDUs
// at least two.
func Parse(b []byte) (TPDU, error) {
	if len(b) == 0 {
		return TPDU{}, fmt.Errorf("%w: apdu: empty TPDU", knx.ErrMalformed)
	}
	t, err := ParseTPCI(b[0])
	if err != nil {
		return TPDU{}, err
	}
	if t.IsControl() {
		if len(b) != 1 {
			return TPDU{}, fmt.Errorf("%w: apdu: %s with %d octets", knx.ErrMalformed, t.Kind, len(b))
		}
		return TPDU{TPCI: t}, nil
	}
	if len(b) < 2 {
		return TPDU{}, fmt.Errorf("%w: apdu: %s of one octet has no APCI", knx.ErrMalformed, t.Kind)
	}
	raw := APCI(b[0]&0x03)<<8 | APCI(b[1])
	p := TPDU{TPCI: t}
	if raw.Has6BitData() {
		p.APCI, p.Short = raw&0x3C0, uint8(raw&0x3F)
	} else {
		p.APCI = raw
	}
	if len(b) > 2 {
		p.Data = append([]byte(nil), b[2:]...)
	}
	return p, nil
}

// Append appends the encoded TPDU.
func (p TPDU) Append(b []byte) []byte {
	o := p.TPCI.Octet()
	if p.TPCI.IsControl() {
		return append(b, o)
	}
	a := p.APCI & 0x3FF
	if a.Has6BitData() {
		a = a&0x3C0 | APCI(p.Short&0x3F)
	}
	b = append(b, o|byte(a>>8), byte(a))
	return append(b, p.Data...)
}

// Bytes returns the encoded TPDU.
func (p TPDU) Bytes() []byte { return p.Append(make([]byte, 0, 2+len(p.Data))) }

// GroupValue is the data of A_GroupValue_Write or _Response. Values of at
// most 6 bits (DPT 1, 2, 3...) are sent "small", in the APCI octet; Data
// then holds one octet 0..63.
type GroupValue struct {
	Data  []byte
	Small bool
}

// GroupValueRead returns the TPDU of A_GroupValue_Read.
func GroupValueRead() []byte { return []byte{0x00, 0x00} }

// GroupValueWrite returns the TPDU of A_GroupValue_Write with v.
func GroupValueWrite(v GroupValue) ([]byte, error) { return groupValue(GroupValueWriteService, v) }

// GroupValueResponse returns the TPDU of A_GroupValue_Response with v.
func GroupValueResponse(v GroupValue) ([]byte, error) {
	return groupValue(GroupValueResponseService, v)
}

func groupValue(s APCI, v GroupValue) ([]byte, error) {
	if v.Small {
		if len(v.Data) != 1 || v.Data[0] > 0x3F {
			return nil, fmt.Errorf("%w: apdu: a small group value is one octet 0..63, got % X", knx.ErrInvalidValue, v.Data)
		}
		return TPDU{APCI: s, Short: v.Data[0]}.Bytes(), nil
	}
	if len(v.Data) == 0 || len(v.Data) > 254 {
		return nil, fmt.Errorf("%w: apdu: group value of %d octets (1..254)", knx.ErrInvalidValue, len(v.Data))
	}
	return TPDU{APCI: s, Data: v.Data}.Bytes(), nil
}

// ParseGroupValue decodes the TPDU of a group value service: it returns
// the service (GroupValueRead, GroupValueResponse or GroupValueWrite) and,
// except for reads, the value. Other TPDUs give an error matching
// knx.ErrUnsupported.
func ParseGroupValue(tpdu []byte) (APCI, GroupValue, error) {
	p, err := Parse(tpdu)
	if err != nil {
		return 0, GroupValue{}, err
	}
	if p.TPCI.Kind != TData {
		return 0, GroupValue{}, fmt.Errorf("%w: apdu: %s is not a group value service", knx.ErrUnsupported, p.TPCI.Kind)
	}
	switch p.APCI {
	case GroupValueReadService:
		if p.Short != 0 || len(p.Data) != 0 {
			return 0, GroupValue{}, fmt.Errorf("%w: apdu: A_GroupValue_Read with data", knx.ErrMalformed)
		}
		return p.APCI, GroupValue{}, nil
	case GroupValueResponseService, GroupValueWriteService:
		if len(p.Data) == 0 {
			return p.APCI, GroupValue{Data: []byte{p.Short}, Small: true}, nil
		}
		return p.APCI, GroupValue{Data: p.Data}, nil
	}
	return 0, GroupValue{}, fmt.Errorf("%w: apdu: %s is not a group value service", knx.ErrUnsupported, p.APCI)
}
