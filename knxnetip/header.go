// SPDX-License-Identifier: MIT

package knxnetip

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/otfabric/go-knx"
)

// Protocol constants.
const (
	// HeaderLen is the length of the KNXnet/IP header.
	HeaderLen = 6
	// Version10 is the KNXnet/IP protocol version 1.0 of the header.
	Version10 = 0x10
	// Port is the KNXnet/IP UDP and TCP port.
	Port = 3671
	// MaxFrameLen bounds the frames this package decodes and encodes.
	// The total length field has 16 bits; UDP datagrams of KNXnet/IP are
	// far shorter (a cEMI frame carries at most 255 octets of NPDU).
	MaxFrameLen = 1024
)

// MulticastAddress is the KNXnet/IP system setup multicast address used
// by discovery and, by default, routing.
var MulticastAddress = netip.AddrFrom4([4]byte{224, 0, 23, 12})

// ServiceType is a KNXnet/IP service type identifier.
type ServiceType uint16

// Service type identifiers.
const (
	SearchRequestType              ServiceType = 0x0201
	SearchResponseType             ServiceType = 0x0202
	DescriptionRequestType         ServiceType = 0x0203
	DescriptionResponseType        ServiceType = 0x0204
	ConnectRequestType             ServiceType = 0x0205
	ConnectResponseType            ServiceType = 0x0206
	ConnectionStateRequestType     ServiceType = 0x0207
	ConnectionStateResponseType    ServiceType = 0x0208
	DisconnectRequestType          ServiceType = 0x0209
	DisconnectResponseType         ServiceType = 0x020A
	SearchRequestExtType           ServiceType = 0x020B
	SearchResponseExtType          ServiceType = 0x020C
	DeviceConfigurationRequestType ServiceType = 0x0310
	DeviceConfigurationAckType     ServiceType = 0x0311
	TunnellingRequestType          ServiceType = 0x0420
	TunnellingAckType              ServiceType = 0x0421
	TunnellingFeatureGetType       ServiceType = 0x0422
	TunnellingFeatureResponseType  ServiceType = 0x0423
	TunnellingFeatureSetType       ServiceType = 0x0424
	TunnellingFeatureInfoType      ServiceType = 0x0425
	RoutingIndicationType          ServiceType = 0x0530
	RoutingLostMessageType         ServiceType = 0x0531
	RoutingBusyType                ServiceType = 0x0532
	RoutingSystemBroadcastType     ServiceType = 0x0533
	SecureWrapperType              ServiceType = 0x0950
	SessionRequestType             ServiceType = 0x0951
	SessionResponseType            ServiceType = 0x0952
	SessionAuthenticateType        ServiceType = 0x0953
	SessionStatusType              ServiceType = 0x0954
	TimerNotifyType                ServiceType = 0x0955
)

var serviceNames = map[ServiceType]string{
	SearchRequestType:              "SEARCH_REQUEST",
	SearchResponseType:             "SEARCH_RESPONSE",
	DescriptionRequestType:         "DESCRIPTION_REQUEST",
	DescriptionResponseType:        "DESCRIPTION_RESPONSE",
	ConnectRequestType:             "CONNECT_REQUEST",
	ConnectResponseType:            "CONNECT_RESPONSE",
	ConnectionStateRequestType:     "CONNECTIONSTATE_REQUEST",
	ConnectionStateResponseType:    "CONNECTIONSTATE_RESPONSE",
	DisconnectRequestType:          "DISCONNECT_REQUEST",
	DisconnectResponseType:         "DISCONNECT_RESPONSE",
	SearchRequestExtType:           "SEARCH_REQUEST_EXTENDED",
	SearchResponseExtType:          "SEARCH_RESPONSE_EXTENDED",
	DeviceConfigurationRequestType: "DEVICE_CONFIGURATION_REQUEST",
	DeviceConfigurationAckType:     "DEVICE_CONFIGURATION_ACK",
	TunnellingRequestType:          "TUNNELLING_REQUEST",
	TunnellingAckType:              "TUNNELLING_ACK",
	TunnellingFeatureGetType:       "TUNNELLING_FEATURE_GET",
	TunnellingFeatureResponseType:  "TUNNELLING_FEATURE_RESPONSE",
	TunnellingFeatureSetType:       "TUNNELLING_FEATURE_SET",
	TunnellingFeatureInfoType:      "TUNNELLING_FEATURE_INFO",
	RoutingIndicationType:          "ROUTING_INDICATION",
	RoutingLostMessageType:         "ROUTING_LOST_MESSAGE",
	RoutingBusyType:                "ROUTING_BUSY",
	RoutingSystemBroadcastType:     "ROUTING_SYSTEM_BROADCAST",
	SecureWrapperType:              "SECURE_WRAPPER",
	SessionRequestType:             "SESSION_REQUEST",
	SessionResponseType:            "SESSION_RESPONSE",
	SessionAuthenticateType:        "SESSION_AUTHENTICATE",
	SessionStatusType:              "SESSION_STATUS",
	TimerNotifyType:                "TIMER_NOTIFY",
}

// String returns the name of the service type, such as
// "TUNNELLING_REQUEST", or "0x%04X" for an unknown one.
func (t ServiceType) String() string {
	if n, ok := serviceNames[t]; ok {
		return n
	}
	return fmt.Sprintf("0x%04X", uint16(t))
}

// Known reports whether this package decodes the service type.
func (t ServiceType) Known() bool { _, ok := serviceNames[t]; return ok }

// Family returns the service family the identifier belongs to (its high
// octet).
func (t ServiceType) Family() ServiceFamilyID { return ServiceFamilyID(t >> 8) }

// Header is the KNXnet/IP header.
type Header struct {
	// Service is the service type identifier.
	Service ServiceType
	// Length is the total length of the frame, header included.
	Length uint16
}

// ParseHeader decodes the header at the start of b. It checks the header
// length and protocol version octets and that Length covers the header;
// it does not require b to hold the whole frame (see [Parse]).
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderLen {
		return Header{}, malformed("header: %d octets, want %d", len(b), HeaderLen)
	}
	if b[0] != HeaderLen {
		return Header{}, malformed("header length 0x%02X, want 0x06", b[0])
	}
	if b[1] != Version10 {
		return Header{}, fmt.Errorf("%w: KNXnet/IP protocol version 0x%02X", knx.ErrUnsupported, b[1])
	}
	h := Header{Service: ServiceType(binary.BigEndian.Uint16(b[2:])), Length: binary.BigEndian.Uint16(b[4:])}
	if h.Length < HeaderLen {
		return Header{}, malformed("total length %d shorter than the header", h.Length)
	}
	return h, nil
}

// AppendHeader appends a header for service with a body of bodyLen octets.
func AppendHeader(b []byte, service ServiceType, bodyLen int) []byte {
	return append(b, HeaderLen, Version10, byte(service>>8), byte(service), byte((bodyLen+HeaderLen)>>8), byte(bodyLen+HeaderLen))
}

func malformed(format string, a ...any) error {
	return fmt.Errorf("%w: knxnetip: %s", knx.ErrMalformed, fmt.Sprintf(format, a...))
}
