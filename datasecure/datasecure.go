// SPDX-License-Identifier: MIT

// Package datasecure implements KNX Data Secure for group communication:
// the S-A_Data service that authenticates, and optionally encrypts, the
// APDU of a telegram end to end with a group key and a 48-bit sequence
// number per sender.
//
// The implementation follows public sources, not the KNX application note
// 158 (see docs/standards/SPECIFICATIONS.md, "KNX Secure sources"). Point
// to point security (tool and device keys, S-A_Sync) is not implemented.
package datasecure

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/internal/ccm"
)

// Key is an AES-128 group key.
type Key [16]byte

// Algorithm is the security algorithm of the security control field.
type Algorithm uint8

// Algorithms.
const (
	// AuthOnly authenticates the APDU, which stays readable.
	AuthOnly Algorithm = 0
	// AuthConf authenticates and encrypts the APDU.
	AuthConf Algorithm = 1
)

// Service is the security service of the security control field.
type Service uint8

// Services.
const (
	SData    Service = 0 // S-A_Data
	SSyncReq Service = 2 // S-A_Sync_Req
	SSyncRes Service = 3 // S-A_Sync_Res
)

// SCF is the security control field.
type SCF struct {
	ToolAccess      bool
	Algorithm       Algorithm
	SystemBroadcast bool
	Service         Service
}

// Byte returns the encoded field.
func (s SCF) Byte() byte {
	b := byte(s.Algorithm&0x07)<<4 | byte(s.Service&0x07)
	if s.ToolAccess {
		b |= 0x80
	}
	if s.SystemBroadcast {
		b |= 0x08
	}
	return b
}

// ParseSCF decodes a security control field.
func ParseSCF(b byte) SCF {
	return SCF{ToolAccess: b&0x80 != 0, Algorithm: Algorithm(b >> 4 & 0x07), SystemBroadcast: b&0x08 != 0, Service: Service(b & 0x07)}
}

// GroupData is the SCF of secured group communication: S-A_Data with
// authentication and confidentiality.
var GroupData = SCF{Algorithm: AuthConf, Service: SData}

// MaxSequence is the largest sequence number.
const MaxSequence = 1<<48 - 1

const (
	macLen = 4
	// overhead is what S-A_Data adds to the plain APDU: the secure APCI
	// is in the place of the plain one, then the SCF, the sequence
	// number and the MAC.
	overhead = 1 + 6 + macLen
)

// IsSecure reports whether the frame carries a secure APDU (APCI
// 0x3F1).
func IsSecure(f *cemi.LData) bool {
	return len(f.TPDU) >= 2 && f.TPDU[0]&0x03 == 0x03 && f.TPDU[1] == 0xF1
}

// Seal returns a copy of f whose APDU is replaced by the S-A_Data of it,
// sent with sequence number seq. The frame becomes an extended frame when
// the secured APDU does not fit a standard one.
func Seal(key Key, f *cemi.LData, seq uint64, scf SCF) (*cemi.LData, error) {
	if seq > MaxSequence {
		return nil, fmt.Errorf("%w: datasecure: sequence %d exceeds 48 bits", knx.ErrInvalidValue, seq)
	}
	if len(f.TPDU) < 2 {
		return nil, fmt.Errorf("%w: datasecure: TPDU of %d octets has no APDU", knx.ErrInvalidValue, len(f.TPDU))
	}
	if len(f.TPDU)+overhead > 256 {
		return nil, fmt.Errorf("%w: datasecure: APDU of %d octets too long", knx.ErrInvalidValue, len(f.TPDU)-1)
	}
	plain := plainAPDU(f.TPDU)
	out := f.Clone()
	tpdu := make([]byte, 0, len(f.TPDU)+overhead)
	tpdu = append(tpdu, f.TPDU[0]&0xFC|byte(apdu.SecureService>>8), byte(apdu.SecureService&0xFF), scf.Byte())
	seqb := put48(seq)
	tpdu = append(tpdu, seqb[:]...)
	b0 := block0(out, tpdu[0], seqb, plain, scf)
	switch scf.Algorithm {
	case AuthOnly:
		mac := ccm.MAC(key[:], b0, append([]byte{scf.Byte()}, plain...), nil)
		tpdu = append(append(tpdu, plain...), mac[:macLen]...)
	case AuthConf:
		mac := ccm.MAC(key[:], b0, []byte{scf.Byte()}, plain)
		// One key stream: the truncated MAC first, then the APDU.
		s := ccm.XOR(key[:], ctr0(out, seqb), append(mac[:macLen:macLen], plain...))
		tpdu = append(append(tpdu, s[macLen:]...), s[:macLen]...)
	default:
		return nil, fmt.Errorf("%w: datasecure: algorithm %d", knx.ErrUnsupported, scf.Algorithm)
	}
	out.TPDU = tpdu
	if len(tpdu)-1 > cemi.MaxStandardNPDU {
		out.Ctrl1 &^= cemi.Ctrl1Standard
	}
	return out, nil
}

// Open verifies, and decrypts, the S-A_Data of a frame and returns the
// plain frame, the sender's sequence number and the SCF. The caller
// checks the sequence number against the sender's last one.
func Open(key Key, f *cemi.LData) (*cemi.LData, uint64, SCF, error) {
	if !IsSecure(f) || len(f.TPDU) < 2+overhead {
		return nil, 0, SCF{}, fmt.Errorf("%w: datasecure: not a secure APDU", knx.ErrMalformed)
	}
	scf := ParseSCF(f.TPDU[2])
	if scf.Service != SData {
		return nil, 0, scf, fmt.Errorf("%w: datasecure: security service %d", knx.ErrUnsupported, scf.Service)
	}
	var seqb [6]byte
	copy(seqb[:], f.TPDU[3:9])
	body := f.TPDU[9 : len(f.TPDU)-macLen]
	got := f.TPDU[len(f.TPDU)-macLen:]
	var plain []byte
	switch scf.Algorithm {
	case AuthOnly:
		plain = body
		mac := ccm.MAC(key[:], block0(f, f.TPDU[0], seqb, nil, scf), append([]byte{scf.Byte()}, plain...), nil)
		if subtle.ConstantTimeCompare(mac[:macLen], got) != 1 {
			return nil, 0, scf, fmt.Errorf("%w: datasecure: authentication failed", knx.ErrSecurity)
		}
	case AuthConf:
		s := ccm.XOR(key[:], ctr0(f, seqb), append(got[:macLen:macLen], body...))
		plain = s[macLen:]
		want := ccm.MAC(key[:], block0(f, f.TPDU[0], seqb, plain, scf), []byte{scf.Byte()}, plain)
		if subtle.ConstantTimeCompare(s[:macLen], want[:macLen]) != 1 {
			return nil, 0, scf, fmt.Errorf("%w: datasecure: authentication failed", knx.ErrSecurity)
		}
	default:
		return nil, 0, scf, fmt.Errorf("%w: datasecure: algorithm %d", knx.ErrUnsupported, scf.Algorithm)
	}
	if len(plain) < 2 {
		return nil, 0, scf, fmt.Errorf("%w: datasecure: plain APDU of %d octets", knx.ErrMalformed, len(plain))
	}
	out := f.Clone()
	out.TPDU = append([]byte{f.TPDU[0]&0xFC | plain[0]&0x03}, plain[1:]...)
	if len(out.TPDU)-1 <= cemi.MaxStandardNPDU {
		out.Ctrl1 |= cemi.Ctrl1Standard
	}
	return out, uint48(seqb), scf, nil
}

// plainAPDU is the APDU of a TPDU without the TPCI bits.
func plainAPDU(tpdu []byte) []byte {
	return append([]byte{tpdu[0] & 0x03}, tpdu[1:]...)
}

// block0 is the CCM block 0: sequence number, addresses, frame flags
// (address type and extended frame format), the TPCI and secure APCI,
// and the payload length (0 for authentication only).
func block0(f *cemi.LData, tpci byte, seq [6]byte, plain []byte, scf SCF) []byte {
	b := make([]byte, 0, 16)
	b = append(b, seq[:]...)
	b = binary.BigEndian.AppendUint16(b, uint16(f.Source))
	b = binary.BigEndian.AppendUint16(b, f.Destination)
	n := 0
	if scf.Algorithm == AuthConf {
		n = len(plain)
	}
	return append(b, 0, f.Ctrl2&(cemi.Ctrl2GroupAddress|0x0F), tpci&0xFC|byte(apdu.SecureService>>8), byte(apdu.SecureService&0xFF), 0, byte(n))
}

// ctr0 is the CCM counter 0.
func ctr0(f *cemi.LData, seq [6]byte) []byte {
	b := make([]byte, 0, 16)
	b = append(b, seq[:]...)
	b = binary.BigEndian.AppendUint16(b, uint16(f.Source))
	b = binary.BigEndian.AppendUint16(b, f.Destination)
	return append(b, 0, 0, 0, 0, 0x01, 0x00)
}

func put48(v uint64) (b [6]byte) {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	copy(b[:], x[2:])
	return b
}

func uint48(b [6]byte) uint64 {
	var x [8]byte
	copy(x[2:], b[:])
	return binary.BigEndian.Uint64(x[:])
}
