// SPDX-License-Identifier: MIT

package knxnetip

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// HostProtocol is the host protocol code of an HPAI.
type HostProtocol uint8

// Host protocol codes.
const (
	IPv4UDP HostProtocol = 0x01
	IPv4TCP HostProtocol = 0x02
)

// String returns "UDP", "TCP" or "0x%02X".
func (p HostProtocol) String() string {
	switch p {
	case IPv4UDP:
		return "UDP"
	case IPv4TCP:
		return "TCP"
	default:
		return fmt.Sprintf("0x%02X", uint8(p))
	}
}

// HPAILen is the length of an IPv4 HPAI.
const HPAILen = 8

// HPAI is a host protocol address information structure: an IPv4 endpoint
// and its protocol. The unspecified endpoint 0.0.0.0:0 ("route back", or
// NAT mode) asks the peer to answer to the source of the datagram.
type HPAI struct {
	Protocol HostProtocol
	Addr     netip.AddrPort
}

// NewHPAI returns an HPAI for UDP endpoint ap; an invalid or IPv6 ap gives
// the route back endpoint 0.0.0.0:0.
func NewHPAI(ap netip.AddrPort) HPAI {
	a := ap.Addr().Unmap()
	if !a.Is4() {
		return RouteBackHPAI()
	}
	return HPAI{Protocol: IPv4UDP, Addr: netip.AddrPortFrom(a, ap.Port())}
}

// RouteBackHPAI returns the UDP route back endpoint 0.0.0.0:0.
func RouteBackHPAI() HPAI {
	return HPAI{Protocol: IPv4UDP, Addr: netip.AddrPortFrom(netip.IPv4Unspecified(), 0)}
}

// TCPHPAI returns the HPAI a client over TCP sends: protocol TCP with the
// endpoint 0.0.0.0:0.
func TCPHPAI() HPAI {
	return HPAI{Protocol: IPv4TCP, Addr: netip.AddrPortFrom(netip.IPv4Unspecified(), 0)}
}

// IsRouteBack reports whether the endpoint is 0.0.0.0 or port 0, which
// means "answer to the source address of the datagram".
func (h HPAI) IsRouteBack() bool {
	return !h.Addr.Addr().IsValid() || h.Addr.Addr().IsUnspecified() || h.Addr.Port() == 0
}

// String returns "UDP 192.168.1.10:3671".
func (h HPAI) String() string { return h.Protocol.String() + " " + h.Addr.String() }

// AppendTo appends the encoded HPAI.
func (h HPAI) AppendTo(b []byte) []byte {
	a := h.Addr.Addr().Unmap()
	ip := [4]byte{}
	if a.Is4() {
		ip = a.As4()
	}
	return append(b, HPAILen, byte(h.Protocol), ip[0], ip[1], ip[2], ip[3], byte(h.Addr.Port()>>8), byte(h.Addr.Port()))
}

// ParseHPAI decodes an HPAI at the start of b and returns the remaining
// octets.
func ParseHPAI(b []byte) (HPAI, []byte, error) {
	if len(b) < HPAILen {
		return HPAI{}, nil, malformed("HPAI: %d octets, want %d", len(b), HPAILen)
	}
	if b[0] != HPAILen {
		return HPAI{}, nil, malformed("HPAI length %d, want %d", b[0], HPAILen)
	}
	p := HostProtocol(b[1])
	if p != IPv4UDP && p != IPv4TCP {
		return HPAI{}, nil, malformed("HPAI host protocol 0x%02X", b[1])
	}
	ip := netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})
	return HPAI{Protocol: p, Addr: netip.AddrPortFrom(ip, binary.BigEndian.Uint16(b[6:]))}, b[HPAILen:], nil
}
