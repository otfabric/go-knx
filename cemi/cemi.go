// SPDX-License-Identifier: MIT

// Package cemi encodes and decodes frames of the common External Message
// Interface (cEMI): the data link layer messages (L_Data, L_Busmon, L_Raw)
// that KNXnet/IP tunnelling and routing carry, and the local device
// management messages (M_PropRead, M_PropWrite, M_Reset, function
// properties) of KNXnet/IP device management.
//
// The transport and application layers inside an L_Data frame (TPCI,
// APCI) are kept as octets here; package apdu decodes them.
package cemi

import (
	"encoding/binary"
	"fmt"

	"github.com/otfabric/go-knx"
)

// MessageCode is the cEMI message code.
type MessageCode uint8

// Message codes.
const (
	LRawReq               MessageCode = 0x10
	LDataReq              MessageCode = 0x11
	LPollDataReq          MessageCode = 0x13
	LPollDataCon          MessageCode = 0x25
	LDataInd              MessageCode = 0x29
	LBusmonInd            MessageCode = 0x2B
	LRawInd               MessageCode = 0x2D
	LDataCon              MessageCode = 0x2E
	LRawCon               MessageCode = 0x2F
	MResetInd             MessageCode = 0xF0
	MResetReq             MessageCode = 0xF1
	MPropWriteCon         MessageCode = 0xF5
	MPropWriteReq         MessageCode = 0xF6
	MPropInfoInd          MessageCode = 0xF7
	MFuncPropCommandReq   MessageCode = 0xF8
	MFuncPropStateReadReq MessageCode = 0xF9
	MFuncPropCon          MessageCode = 0xFA
	MPropReadCon          MessageCode = 0xFB
	MPropReadReq          MessageCode = 0xFC
)

var codeNames = map[MessageCode]string{
	LRawReq: "L_Raw.req", LDataReq: "L_Data.req", LPollDataReq: "L_Poll_Data.req", LPollDataCon: "L_Poll_Data.con",
	LDataInd: "L_Data.ind", LBusmonInd: "L_Busmon.ind", LRawInd: "L_Raw.ind", LDataCon: "L_Data.con", LRawCon: "L_Raw.con",
	MResetInd: "M_Reset.ind", MResetReq: "M_Reset.req", MPropWriteCon: "M_PropWrite.con", MPropWriteReq: "M_PropWrite.req",
	MPropInfoInd: "M_PropInfo.ind", MFuncPropCommandReq: "M_FuncPropCommand.req", MFuncPropStateReadReq: "M_FuncPropStateRead.req",
	MFuncPropCon: "M_FuncProp.con", MPropReadCon: "M_PropRead.con", MPropReadReq: "M_PropRead.req",
}

// String names the message code, such as "L_Data.ind".
func (c MessageCode) String() string {
	if n, ok := codeNames[c]; ok {
		return n
	}
	return fmt.Sprintf("0x%02X", uint8(c))
}

// Frame is a decoded cEMI frame.
type Frame interface {
	// Code returns the message code.
	Code() MessageCode
	// AppendTo appends the encoded frame.
	AppendTo(b []byte) ([]byte, error)
}

// Marshal returns the encoded frame.
func Marshal(f Frame) ([]byte, error) { return f.AppendTo(make([]byte, 0, 32)) }

// Parse decodes the cEMI frame that fills b. Message codes this package
// does not decode give *[Unknown].
func Parse(b []byte) (Frame, error) {
	if len(b) < 1 {
		return nil, malformed("empty frame")
	}
	c := MessageCode(b[0])
	switch c {
	case LDataReq, LDataInd, LDataCon, LPollDataReq, LPollDataCon:
		if c == LPollDataReq || c == LPollDataCon {
			break
		}
		return parseLData(b)
	case LBusmonInd, LRawReq, LRawInd, LRawCon:
		return parseRaw(b)
	case MPropReadReq, MPropReadCon, MPropWriteReq, MPropWriteCon, MPropInfoInd:
		return parseProperty(b)
	case MFuncPropCommandReq, MFuncPropStateReadReq, MFuncPropCon:
		return parseFuncProp(b)
	case MResetReq, MResetInd:
		if len(b) != 1 {
			return nil, malformed("%s: %d octets, want 1", c, len(b))
		}
		return &Reset{MsgCode: c}, nil
	}
	return &Unknown{MsgCode: c, Data: clone(b[1:])}, nil
}

// AdditionalInfo is an additional information block of an L_Data,
// L_Busmon or L_Raw frame (RF info, timestamps, busmonitor status...).
type AdditionalInfo struct {
	Type uint8
	Data []byte
}

// Additional information types used by this package.
const (
	AddInfoPLMedium         uint8 = 0x01
	AddInfoRFMedium         uint8 = 0x02
	AddInfoBusmonitorStatus uint8 = 0x03
	AddInfoTimestamp        uint8 = 0x04
	AddInfoTimeDelay        uint8 = 0x05
	AddInfoExtTimestamp     uint8 = 0x06
	AddInfoBiBatInfo        uint8 = 0x07
	AddInfoRFMultiInfo      uint8 = 0x08
	AddInfoPreambleInfo     uint8 = 0x09
	AddInfoRFFastAckInfo    uint8 = 0x0A
	AddInfoManufacturer     uint8 = 0xFE
)

func appendAddInfo(b []byte, infos []AdditionalInfo) ([]byte, error) {
	n := 0
	for _, a := range infos {
		if len(a.Data) > 255 {
			return nil, fmt.Errorf("%w: cemi: additional information of %d octets", knx.ErrInvalidValue, len(a.Data))
		}
		n += 2 + len(a.Data)
	}
	if n > 255 {
		return nil, fmt.Errorf("%w: cemi: additional information of %d octets", knx.ErrInvalidValue, n)
	}
	b = append(b, byte(n))
	for _, a := range infos {
		b = append(b, a.Type, byte(len(a.Data)))
		b = append(b, a.Data...)
	}
	return b, nil
}

// parseAddInfo decodes the additional information after the message code
// and returns the rest of the frame.
func parseAddInfo(b []byte) ([]AdditionalInfo, []byte, error) {
	if len(b) < 2 {
		return nil, nil, malformed("%s: %d octets", MessageCode(b[0]), len(b))
	}
	n := int(b[1])
	if 2+n > len(b) {
		return nil, nil, malformed("additional information length %d with %d octets left", n, len(b)-2)
	}
	p := b[2 : 2+n]
	var infos []AdditionalInfo
	for len(p) > 0 {
		if len(p) < 2 || 2+int(p[1]) > len(p) {
			return nil, nil, malformed("additional information block: %d octets left", len(p))
		}
		infos = append(infos, AdditionalInfo{Type: p[0], Data: clone(p[2 : 2+int(p[1])])})
		p = p[2+int(p[1]):]
	}
	return infos, b[2+n:], nil
}

// Raw is an L_Busmon.ind, L_Raw.req, L_Raw.ind or L_Raw.con frame: the
// additional information and the raw link layer frame.
type Raw struct {
	MsgCode MessageCode
	AddInfo []AdditionalInfo
	Data    []byte
}

// Code returns the message code.
func (r *Raw) Code() MessageCode { return r.MsgCode }

// AppendTo appends the encoded frame.
func (r *Raw) AppendTo(b []byte) ([]byte, error) {
	b, err := appendAddInfo(append(b, byte(r.MsgCode)), r.AddInfo)
	if err != nil {
		return nil, err
	}
	return append(b, r.Data...), nil
}

func parseRaw(b []byte) (Frame, error) {
	infos, rest, err := parseAddInfo(b)
	if err != nil {
		return nil, err
	}
	return &Raw{MsgCode: MessageCode(b[0]), AddInfo: infos, Data: clone(rest)}, nil
}

// Reset is M_Reset.req or M_Reset.ind.
type Reset struct{ MsgCode MessageCode }

// Code returns the message code.
func (r *Reset) Code() MessageCode { return r.MsgCode }

// AppendTo appends the encoded frame.
func (r *Reset) AppendTo(b []byte) ([]byte, error) { return append(b, byte(r.MsgCode)), nil }

// Unknown keeps a frame of a message code this package does not decode.
type Unknown struct {
	MsgCode MessageCode
	Data    []byte
}

// Code returns the message code.
func (u *Unknown) Code() MessageCode { return u.MsgCode }

// AppendTo appends the encoded frame.
func (u *Unknown) AppendTo(b []byte) ([]byte, error) {
	return append(append(b, byte(u.MsgCode)), u.Data...), nil
}

// Property is an M_PropRead.req/.con, M_PropWrite.req/.con or
// M_PropInfo.ind frame: an interface object property access. In a
// negative confirmation Count is 0 and Data holds the error code.
type Property struct {
	MsgCode    MessageCode
	ObjectType uint16
	Instance   uint8
	PropertyID uint8
	// Count is the number of elements (0..15).
	Count uint8
	// Start is the start index (0..4095).
	Start uint16
	Data  []byte
}

// Code returns the message code.
func (p *Property) Code() MessageCode { return p.MsgCode }

// AppendTo appends the encoded frame.
func (p *Property) AppendTo(b []byte) ([]byte, error) {
	if p.Count > 15 || p.Start > 0x0FFF {
		return nil, fmt.Errorf("%w: cemi: %s count %d (0..15), start %d (0..4095)", knx.ErrInvalidValue, p.MsgCode, p.Count, p.Start)
	}
	b = append(b, byte(p.MsgCode))
	b = binary.BigEndian.AppendUint16(b, p.ObjectType)
	b = append(b, p.Instance, p.PropertyID)
	b = binary.BigEndian.AppendUint16(b, uint16(p.Count)<<12|p.Start)
	return append(b, p.Data...), nil
}

func parseProperty(b []byte) (Frame, error) {
	if len(b) < 7 {
		return nil, malformed("%s: %d octets, want at least 7", MessageCode(b[0]), len(b))
	}
	p := &Property{
		MsgCode:    MessageCode(b[0]),
		ObjectType: binary.BigEndian.Uint16(b[1:]),
		Instance:   b[3],
		PropertyID: b[4],
		Count:      b[5] >> 4,
		Start:      binary.BigEndian.Uint16(b[5:]) & 0x0FFF,
		Data:       clone(b[7:]),
	}
	if p.MsgCode == MPropReadReq && len(p.Data) != 0 {
		return nil, malformed("%s: %d data octets", p.MsgCode, len(p.Data))
	}
	return p, nil
}

// FunctionProperty is M_FuncPropCommand.req, M_FuncPropStateRead.req or
// M_FuncProp.con.
type FunctionProperty struct {
	MsgCode    MessageCode
	ObjectType uint16
	Instance   uint8
	PropertyID uint8
	Data       []byte
}

// Code returns the message code.
func (p *FunctionProperty) Code() MessageCode { return p.MsgCode }

// AppendTo appends the encoded frame.
func (p *FunctionProperty) AppendTo(b []byte) ([]byte, error) {
	b = append(b, byte(p.MsgCode))
	b = binary.BigEndian.AppendUint16(b, p.ObjectType)
	b = append(b, p.Instance, p.PropertyID)
	return append(b, p.Data...), nil
}

func parseFuncProp(b []byte) (Frame, error) {
	if len(b) < 5 {
		return nil, malformed("%s: %d octets, want at least 5", MessageCode(b[0]), len(b))
	}
	return &FunctionProperty{MsgCode: MessageCode(b[0]), ObjectType: binary.BigEndian.Uint16(b[1:]), Instance: b[3], PropertyID: b[4], Data: clone(b[5:])}, nil
}

func malformed(format string, a ...any) error {
	return fmt.Errorf("%w: cemi: %s", knx.ErrMalformed, fmt.Sprintf(format, a...))
}

func clone(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return append([]byte(nil), b...)
}
