// SPDX-License-Identifier: MIT

package knxnetip

import (
	"encoding/binary"
	"fmt"

	"github.com/otfabric/go-knx"
)

// Message is the body of a KNXnet/IP frame of one service type.
type Message interface {
	// Service returns the service type identifier.
	Service() ServiceType
	// AppendBody appends the encoded body (without the header).
	AppendBody(b []byte) []byte
}

// Append appends the frame of m, header included.
func Append(b []byte, m Message) ([]byte, error) {
	start := len(b)
	b = AppendHeader(b, m.Service(), 0)
	b = m.AppendBody(b)
	n := len(b) - start
	if n > MaxFrameLen {
		return b[:start], fmt.Errorf("%w: %s frame of %d octets exceeds %d", errTooLong, m.Service(), n, MaxFrameLen)
	}
	binary.BigEndian.PutUint16(b[start+4:], uint16(n))
	// Never emit what this package would refuse to decode: a structure
	// whose length octet overflowed, a field out of range.
	if _, err := ParseBody(m.Service(), b[start+HeaderLen:]); err != nil {
		return b[:start], fmt.Errorf("%w: %s frame does not encode to a valid frame: %v", knx.ErrInvalidValue, m.Service(), err)
	}
	return b, nil
}

// Marshal returns the frame of m, header included.
func Marshal(m Message) ([]byte, error) { return Append(make([]byte, 0, 64), m) }

// Parse decodes the frame that fills b exactly (a UDP datagram, or a frame
// read from a TCP stream with [ReadFrame]). Unknown service types decode
// to *[Unknown].
func Parse(b []byte) (Message, error) {
	h, err := ParseHeader(b)
	if err != nil {
		return nil, err
	}
	if int(h.Length) != len(b) {
		return nil, malformed("%s: total length %d, datagram %d octets", h.Service, h.Length, len(b))
	}
	if len(b) > MaxFrameLen {
		return nil, malformed("%s: %d octets exceeds %d", h.Service, len(b), MaxFrameLen)
	}
	return ParseBody(h.Service, b[HeaderLen:])
}

// ParseBody decodes the body of a frame of service type t.
func ParseBody(t ServiceType, p []byte) (Message, error) {
	switch t {
	case SearchRequestType:
		h, err := exactHPAI(t, p)
		if err != nil {
			return nil, err
		}
		return &SearchRequest{Discovery: h}, nil
	case SearchRequestExtType:
		return parseSearchRequestExt(p)
	case SearchResponseType, SearchResponseExtType:
		h, rest, err := ParseHPAI(p)
		if err != nil {
			return nil, err
		}
		ds, err := ParseDIBs(rest)
		if err != nil {
			return nil, err
		}
		return &SearchResponse{Extended: t == SearchResponseExtType, Control: h, DIBs: ds}, nil
	case DescriptionRequestType:
		h, err := exactHPAI(t, p)
		if err != nil {
			return nil, err
		}
		return &DescriptionRequest{Control: h}, nil
	case DescriptionResponseType:
		ds, err := ParseDIBs(p)
		if err != nil {
			return nil, err
		}
		return &DescriptionResponse{DIBs: ds}, nil
	case ConnectRequestType:
		ctl, rest, err := ParseHPAI(p)
		if err != nil {
			return nil, err
		}
		data, rest, err := ParseHPAI(rest)
		if err != nil {
			return nil, err
		}
		cri, err := ParseCRI(rest)
		if err != nil {
			return nil, err
		}
		return &ConnectRequest{Control: ctl, Data: data, CRI: cri}, nil
	case ConnectResponseType:
		return parseConnectResponse(p)
	case ConnectionStateRequestType, DisconnectRequestType:
		if len(p) != 2+HPAILen {
			return nil, malformed("%s: body %d octets, want %d", t, len(p), 2+HPAILen)
		}
		h, _, err := ParseHPAI(p[2:])
		if err != nil {
			return nil, err
		}
		if t == DisconnectRequestType {
			return &DisconnectRequest{Channel: p[0], Control: h}, nil
		}
		return &ConnectionStateRequest{Channel: p[0], Control: h}, nil
	case ConnectionStateResponseType, DisconnectResponseType:
		if len(p) != 2 {
			return nil, malformed("%s: body %d octets, want 2", t, len(p))
		}
		if t == DisconnectResponseType {
			return &DisconnectResponse{Channel: p[0], Status: Status(p[1])}, nil
		}
		return &ConnectionStateResponse{Channel: p[0], Status: Status(p[1])}, nil
	case TunnellingRequestType, DeviceConfigurationRequestType:
		ch, seq, _, rest, err := parseConnHeader(t, p)
		if err != nil {
			return nil, err
		}
		if len(rest) < 1 {
			return nil, malformed("%s: no cEMI frame", t)
		}
		if t == DeviceConfigurationRequestType {
			return &DeviceConfigurationRequest{Channel: ch, Seq: seq, CEMI: clone(rest)}, nil
		}
		return &TunnellingRequest{Channel: ch, Seq: seq, CEMI: clone(rest)}, nil
	case TunnellingAckType, DeviceConfigurationAckType:
		ch, seq, st, rest, err := parseConnHeader(t, p)
		if err != nil {
			return nil, err
		}
		if len(rest) != 0 {
			return nil, malformed("%s: %d octets after the connection header", t, len(rest))
		}
		if t == DeviceConfigurationAckType {
			return &DeviceConfigurationAck{Channel: ch, Seq: seq, Status: Status(st)}, nil
		}
		return &TunnellingAck{Channel: ch, Seq: seq, Status: Status(st)}, nil
	case TunnellingFeatureGetType, TunnellingFeatureResponseType, TunnellingFeatureSetType, TunnellingFeatureInfoType:
		ch, seq, _, rest, err := parseConnHeader(t, p)
		if err != nil {
			return nil, err
		}
		if len(rest) < 2 {
			return nil, malformed("%s: feature of %d octets", t, len(rest))
		}
		f := &TunnellingFeature{Type: t, Channel: ch, Seq: seq, Feature: FeatureID(rest[0]), ReturnCode: rest[1], Value: clone(rest[2:])}
		if t == TunnellingFeatureGetType && len(f.Value) != 0 {
			return nil, malformed("%s: %d value octets", t, len(f.Value))
		}
		return f, nil
	case RoutingIndicationType, RoutingSystemBroadcastType:
		if len(p) < 1 {
			return nil, malformed("%s: no cEMI frame", t)
		}
		return &RoutingIndication{SystemBroadcast: t == RoutingSystemBroadcastType, CEMI: clone(p)}, nil
	case RoutingLostMessageType:
		if len(p) != 4 || p[0] != 4 {
			return nil, malformed("%s: body %d octets (length octet %v), want 4", t, len(p), first(p))
		}
		return &RoutingLostMessage{DeviceState: p[1], Lost: binary.BigEndian.Uint16(p[2:])}, nil
	case RoutingBusyType:
		if len(p) != 6 || p[0] != 6 {
			return nil, malformed("%s: body %d octets (length octet %v), want 6", t, len(p), first(p))
		}
		return &RoutingBusy{DeviceState: p[1], WaitTime: binary.BigEndian.Uint16(p[2:]), Control: binary.BigEndian.Uint16(p[4:])}, nil
	case SecureWrapperType, SessionRequestType, SessionResponseType, SessionAuthenticateType, SessionStatusType, TimerNotifyType:
		return parseSecure(t, p)
	}
	return &Unknown{Type: t, Body: clone(p)}, nil
}

func exactHPAI(t ServiceType, p []byte) (HPAI, error) {
	h, rest, err := ParseHPAI(p)
	if err != nil {
		return HPAI{}, err
	}
	if len(rest) != 0 {
		return HPAI{}, malformed("%s: %d octets after the HPAI", t, len(rest))
	}
	return h, nil
}

func parseConnHeader(t ServiceType, p []byte) (ch, seq, status uint8, rest []byte, err error) {
	if len(p) < 4 {
		return 0, 0, 0, nil, malformed("%s: connection header of %d octets", t, len(p))
	}
	if p[0] != 4 {
		return 0, 0, 0, nil, malformed("%s: connection header length %d, want 4", t, p[0])
	}
	return p[1], p[2], p[3], p[4:], nil
}

// SearchRequest is SEARCH_REQUEST: discover KNXnet/IP servers.
type SearchRequest struct {
	// Discovery is the endpoint search responses go to.
	Discovery HPAI
}

// Service returns SearchRequestType.
func (*SearchRequest) Service() ServiceType { return SearchRequestType }

// AppendBody appends the body.
func (m *SearchRequest) AppendBody(b []byte) []byte { return m.Discovery.AppendTo(b) }

// SearchParamType is the type of a search request parameter (SRP).
type SearchParamType uint8

// Search request parameter types.
const (
	SRPInvalid         SearchParamType = 0x01
	SRPProgrammingMode SearchParamType = 0x02
	SRPMACAddress      SearchParamType = 0x03
	SRPService         SearchParamType = 0x04
	SRPRequestDIBs     SearchParamType = 0x05
)

// SearchParam is a search request parameter of SEARCH_REQUEST_EXTENDED.
type SearchParam struct {
	Type SearchParamType
	// Mandatory is bit 7 of the type octet: a server that does not
	// support the parameter must not answer.
	Mandatory bool
	Data      []byte
}

// SearchRequestExt is SEARCH_REQUEST_EXTENDED.
type SearchRequestExt struct {
	Discovery HPAI
	Params    []SearchParam
}

// Service returns SearchRequestExtType.
func (*SearchRequestExt) Service() ServiceType { return SearchRequestExtType }

// AppendBody appends the body.
func (m *SearchRequestExt) AppendBody(b []byte) []byte {
	b = m.Discovery.AppendTo(b)
	for _, p := range m.Params {
		t := byte(p.Type) & 0x7F
		if p.Mandatory {
			t |= 0x80
		}
		b = append(b, byte(2+len(p.Data)), t)
		b = append(b, p.Data...)
	}
	return b
}

func parseSearchRequestExt(p []byte) (Message, error) {
	h, rest, err := ParseHPAI(p)
	if err != nil {
		return nil, err
	}
	m := &SearchRequestExt{Discovery: h}
	for len(rest) > 0 {
		if len(rest) < 2 || int(rest[0]) < 2 || int(rest[0]) > len(rest) {
			return nil, malformed("search parameter: length %v with %d octets left", first(rest), len(rest))
		}
		n := int(rest[0])
		m.Params = append(m.Params, SearchParam{Type: SearchParamType(rest[1] & 0x7F), Mandatory: rest[1]&0x80 != 0, Data: clone(rest[2:n])})
		rest = rest[n:]
	}
	return m, nil
}

// SearchResponse is SEARCH_RESPONSE or, with Extended,
// SEARCH_RESPONSE_EXTENDED.
type SearchResponse struct {
	Extended bool
	// Control is the control endpoint of the server.
	Control HPAI
	DIBs    DIBs
}

// Service returns SearchResponseType or SearchResponseExtType.
func (m *SearchResponse) Service() ServiceType {
	if m.Extended {
		return SearchResponseExtType
	}
	return SearchResponseType
}

// AppendBody appends the body.
func (m *SearchResponse) AppendBody(b []byte) []byte { return m.DIBs.AppendTo(m.Control.AppendTo(b)) }

// DescriptionRequest is DESCRIPTION_REQUEST.
type DescriptionRequest struct {
	// Control is the endpoint the response goes to.
	Control HPAI
}

// Service returns DescriptionRequestType.
func (*DescriptionRequest) Service() ServiceType { return DescriptionRequestType }

// AppendBody appends the body.
func (m *DescriptionRequest) AppendBody(b []byte) []byte { return m.Control.AppendTo(b) }

// DescriptionResponse is DESCRIPTION_RESPONSE.
type DescriptionResponse struct {
	DIBs DIBs
}

// Service returns DescriptionResponseType.
func (*DescriptionResponse) Service() ServiceType { return DescriptionResponseType }

// AppendBody appends the body.
func (m *DescriptionResponse) AppendBody(b []byte) []byte { return m.DIBs.AppendTo(b) }

// ConnectRequest is CONNECT_REQUEST.
type ConnectRequest struct {
	Control HPAI
	Data    HPAI
	CRI     CRI
}

// Service returns ConnectRequestType.
func (*ConnectRequest) Service() ServiceType { return ConnectRequestType }

// AppendBody appends the body.
func (m *ConnectRequest) AppendBody(b []byte) []byte {
	return m.CRI.AppendTo(m.Data.AppendTo(m.Control.AppendTo(b)))
}

// ConnectResponse is CONNECT_RESPONSE. Data and CRD are present when
// Status is E_NO_ERROR.
type ConnectResponse struct {
	Channel uint8
	Status  Status
	Data    HPAI
	CRD     CRD
	// Trailer keeps octets a peer sent after the status of a refusal.
	Trailer []byte
}

// Service returns ConnectResponseType.
func (*ConnectResponse) Service() ServiceType { return ConnectResponseType }

// AppendBody appends the body.
func (m *ConnectResponse) AppendBody(b []byte) []byte {
	b = append(b, m.Channel, byte(m.Status))
	if m.Status != StatusNoError {
		return append(b, m.Trailer...)
	}
	return m.CRD.AppendTo(m.Data.AppendTo(b))
}

func parseConnectResponse(p []byte) (Message, error) {
	if len(p) < 2 {
		return nil, malformed("CONNECT_RESPONSE: body of %d octets", len(p))
	}
	m := &ConnectResponse{Channel: p[0], Status: Status(p[1])}
	if m.Status != StatusNoError {
		m.Trailer = clone(p[2:])
		return m, nil
	}
	h, rest, err := ParseHPAI(p[2:])
	if err != nil {
		return nil, err
	}
	crd, err := ParseCRD(rest)
	if err != nil {
		return nil, err
	}
	m.Data, m.CRD = h, crd
	return m, nil
}

// ConnectionStateRequest is CONNECTIONSTATE_REQUEST (heartbeat).
type ConnectionStateRequest struct {
	Channel uint8
	Control HPAI
}

// Service returns ConnectionStateRequestType.
func (*ConnectionStateRequest) Service() ServiceType { return ConnectionStateRequestType }

// AppendBody appends the body.
func (m *ConnectionStateRequest) AppendBody(b []byte) []byte {
	return m.Control.AppendTo(append(b, m.Channel, 0))
}

// ConnectionStateResponse is CONNECTIONSTATE_RESPONSE.
type ConnectionStateResponse struct {
	Channel uint8
	Status  Status
}

// Service returns ConnectionStateResponseType.
func (*ConnectionStateResponse) Service() ServiceType { return ConnectionStateResponseType }

// AppendBody appends the body.
func (m *ConnectionStateResponse) AppendBody(b []byte) []byte {
	return append(b, m.Channel, byte(m.Status))
}

// DisconnectRequest is DISCONNECT_REQUEST.
type DisconnectRequest struct {
	Channel uint8
	Control HPAI
}

// Service returns DisconnectRequestType.
func (*DisconnectRequest) Service() ServiceType { return DisconnectRequestType }

// AppendBody appends the body.
func (m *DisconnectRequest) AppendBody(b []byte) []byte {
	return m.Control.AppendTo(append(b, m.Channel, 0))
}

// DisconnectResponse is DISCONNECT_RESPONSE.
type DisconnectResponse struct {
	Channel uint8
	Status  Status
}

// Service returns DisconnectResponseType.
func (*DisconnectResponse) Service() ServiceType { return DisconnectResponseType }

// AppendBody appends the body.
func (m *DisconnectResponse) AppendBody(b []byte) []byte {
	return append(b, m.Channel, byte(m.Status))
}

// TunnellingRequest is TUNNELLING_REQUEST: a cEMI frame on a tunnelling
// connection.
type TunnellingRequest struct {
	Channel uint8
	Seq     uint8
	CEMI    []byte
}

// Service returns TunnellingRequestType.
func (*TunnellingRequest) Service() ServiceType { return TunnellingRequestType }

// AppendBody appends the body.
func (m *TunnellingRequest) AppendBody(b []byte) []byte {
	return append(append(b, 4, m.Channel, m.Seq, 0), m.CEMI...)
}

// TunnellingAck is TUNNELLING_ACK.
type TunnellingAck struct {
	Channel uint8
	Seq     uint8
	Status  Status
}

// Service returns TunnellingAckType.
func (*TunnellingAck) Service() ServiceType { return TunnellingAckType }

// AppendBody appends the body.
func (m *TunnellingAck) AppendBody(b []byte) []byte {
	return append(b, 4, m.Channel, m.Seq, byte(m.Status))
}

// DeviceConfigurationRequest is DEVICE_CONFIGURATION_REQUEST: a cEMI
// management frame (M_PropRead and so on) on a device management
// connection.
type DeviceConfigurationRequest struct {
	Channel uint8
	Seq     uint8
	CEMI    []byte
}

// Service returns DeviceConfigurationRequestType.
func (*DeviceConfigurationRequest) Service() ServiceType { return DeviceConfigurationRequestType }

// AppendBody appends the body.
func (m *DeviceConfigurationRequest) AppendBody(b []byte) []byte {
	return append(append(b, 4, m.Channel, m.Seq, 0), m.CEMI...)
}

// DeviceConfigurationAck is DEVICE_CONFIGURATION_ACK.
type DeviceConfigurationAck struct {
	Channel uint8
	Seq     uint8
	Status  Status
}

// Service returns DeviceConfigurationAckType.
func (*DeviceConfigurationAck) Service() ServiceType { return DeviceConfigurationAckType }

// AppendBody appends the body.
func (m *DeviceConfigurationAck) AppendBody(b []byte) []byte {
	return append(b, 4, m.Channel, m.Seq, byte(m.Status))
}

// FeatureID identifies an interface feature of tunnelling v2.
type FeatureID uint8

// Interface features.
const (
	FeatureSupportedEMIType      FeatureID = 0x01
	FeatureDeviceDescriptorType0 FeatureID = 0x02
	FeatureBusConnectionStatus   FeatureID = 0x03
	FeatureManufacturerCode      FeatureID = 0x04
	FeatureActiveEMIType         FeatureID = 0x05
	FeatureIndividualAddress     FeatureID = 0x06
	FeatureMaxAPDULength         FeatureID = 0x07
	FeatureInfoServiceEnable     FeatureID = 0x08
)

// TunnellingFeature is TUNNELLING_FEATURE_GET, _RESPONSE, _SET or _INFO
// (tunnelling v2). ReturnCode is reserved (0) except in a response.
type TunnellingFeature struct {
	Type       ServiceType
	Channel    uint8
	Seq        uint8
	Feature    FeatureID
	ReturnCode uint8
	Value      []byte
}

// Service returns the feature service type.
func (m *TunnellingFeature) Service() ServiceType { return m.Type }

// AppendBody appends the body.
func (m *TunnellingFeature) AppendBody(b []byte) []byte {
	b = append(b, 4, m.Channel, m.Seq, 0, byte(m.Feature), m.ReturnCode)
	return append(b, m.Value...)
}

// RoutingIndication is ROUTING_INDICATION or, with SystemBroadcast,
// ROUTING_SYSTEM_BROADCAST: a cEMI frame routed over IP multicast.
type RoutingIndication struct {
	SystemBroadcast bool
	CEMI            []byte
}

// Service returns RoutingIndicationType or RoutingSystemBroadcastType.
func (m *RoutingIndication) Service() ServiceType {
	if m.SystemBroadcast {
		return RoutingSystemBroadcastType
	}
	return RoutingIndicationType
}

// AppendBody appends the body.
func (m *RoutingIndication) AppendBody(b []byte) []byte { return append(b, m.CEMI...) }

// RoutingLostMessage is ROUTING_LOST_MESSAGE: a router lost telegrams
// because its queue overflowed.
type RoutingLostMessage struct {
	DeviceState uint8
	Lost        uint16
}

// Service returns RoutingLostMessageType.
func (*RoutingLostMessage) Service() ServiceType { return RoutingLostMessageType }

// AppendBody appends the body.
func (m *RoutingLostMessage) AppendBody(b []byte) []byte {
	return binary.BigEndian.AppendUint16(append(b, 4, m.DeviceState), m.Lost)
}

// RoutingBusy is ROUTING_BUSY: flow control; senders pause for WaitTime
// milliseconds.
type RoutingBusy struct {
	DeviceState uint8
	WaitTime    uint16
	Control     uint16
}

// Service returns RoutingBusyType.
func (*RoutingBusy) Service() ServiceType { return RoutingBusyType }

// AppendBody appends the body.
func (m *RoutingBusy) AppendBody(b []byte) []byte {
	b = binary.BigEndian.AppendUint16(append(b, 6, m.DeviceState), m.WaitTime)
	return binary.BigEndian.AppendUint16(b, m.Control)
}

// Unknown keeps a frame of a service type this package does not decode.
type Unknown struct {
	Type ServiceType
	Body []byte
}

// Service returns the service type.
func (m *Unknown) Service() ServiceType { return m.Type }

// AppendBody appends the body.
func (m *Unknown) AppendBody(b []byte) []byte { return append(b, m.Body...) }
