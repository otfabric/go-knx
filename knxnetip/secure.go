// SPDX-License-Identifier: MIT

package knxnetip

import (
	"encoding/binary"
	"errors"
	"io"
)

var errTooLong = errors.New("knxnetip: frame too long")

// MACLen is the length of the CCM message authentication code of KNX IP
// Secure.
const MACLen = 16

// SecureWrapper is SECURE_WRAPPER: an encrypted and authenticated
// KNXnet/IP frame (KNX IP Secure). Package secure produces and opens it.
type SecureWrapper struct {
	SessionID  uint16
	Sequence   [6]byte
	Serial     [6]byte
	MessageTag uint16
	Encrypted  []byte
	MAC        [MACLen]byte
}

// Service returns SecureWrapperType.
func (*SecureWrapper) Service() ServiceType { return SecureWrapperType }

// AppendBody appends the body.
func (m *SecureWrapper) AppendBody(b []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, m.SessionID)
	b = append(b, m.Sequence[:]...)
	b = append(b, m.Serial[:]...)
	b = binary.BigEndian.AppendUint16(b, m.MessageTag)
	b = append(b, m.Encrypted...)
	return append(b, m.MAC[:]...)
}

// SessionRequest is SESSION_REQUEST: the client's X25519 public key.
type SessionRequest struct {
	Control   HPAI
	PublicKey [32]byte
}

// Service returns SessionRequestType.
func (*SessionRequest) Service() ServiceType { return SessionRequestType }

// AppendBody appends the body.
func (m *SessionRequest) AppendBody(b []byte) []byte {
	return append(m.Control.AppendTo(b), m.PublicKey[:]...)
}

// SessionResponse is SESSION_RESPONSE: the session identifier, the
// server's public key and a MAC under the device authentication code.
type SessionResponse struct {
	SessionID uint16
	PublicKey [32]byte
	MAC       [MACLen]byte
}

// Service returns SessionResponseType.
func (*SessionResponse) Service() ServiceType { return SessionResponseType }

// AppendBody appends the body.
func (m *SessionResponse) AppendBody(b []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, m.SessionID)
	b = append(b, m.PublicKey[:]...)
	return append(b, m.MAC[:]...)
}

// SessionAuthenticate is SESSION_AUTHENTICATE: the user and a MAC under
// the user's password key (sent inside a SECURE_WRAPPER).
type SessionAuthenticate struct {
	UserID uint8
	MAC    [MACLen]byte
}

// Service returns SessionAuthenticateType.
func (*SessionAuthenticate) Service() ServiceType { return SessionAuthenticateType }

// AppendBody appends the body.
func (m *SessionAuthenticate) AppendBody(b []byte) []byte {
	return append(append(b, 0, m.UserID), m.MAC[:]...)
}

// SessionStatusCode is the status of SESSION_STATUS.
type SessionStatusCode uint8

// Session status codes.
const (
	SessionAuthSuccess     SessionStatusCode = 0x00
	SessionAuthFailed      SessionStatusCode = 0x01
	SessionUnauthenticated SessionStatusCode = 0x02
	SessionTimeout         SessionStatusCode = 0x03
	SessionKeepAlive       SessionStatusCode = 0x04
	SessionClose           SessionStatusCode = 0x05
)

// SessionStatus is SESSION_STATUS.
type SessionStatus struct {
	Status SessionStatusCode
}

// Service returns SessionStatusType.
func (*SessionStatus) Service() ServiceType { return SessionStatusType }

// AppendBody appends the body.
func (m *SessionStatus) AppendBody(b []byte) []byte { return append(b, byte(m.Status), 0) }

// TimerNotify is TIMER_NOTIFY: secure routing timer synchronisation.
type TimerNotify struct {
	Timer      [6]byte
	Serial     [6]byte
	MessageTag uint16
	MAC        [MACLen]byte
}

// Service returns TimerNotifyType.
func (*TimerNotify) Service() ServiceType { return TimerNotifyType }

// AppendBody appends the body.
func (m *TimerNotify) AppendBody(b []byte) []byte {
	b = append(b, m.Timer[:]...)
	b = append(b, m.Serial[:]...)
	b = binary.BigEndian.AppendUint16(b, m.MessageTag)
	return append(b, m.MAC[:]...)
}

func parseSecure(t ServiceType, p []byte) (Message, error) {
	switch t {
	case SecureWrapperType:
		// session(2) sequence(6) serial(6) tag(2) frame(>=HeaderLen) MAC(16)
		if len(p) < 16+HeaderLen+MACLen {
			return nil, malformed("%s: body of %d octets", t, len(p))
		}
		m := &SecureWrapper{SessionID: binary.BigEndian.Uint16(p), MessageTag: binary.BigEndian.Uint16(p[14:])}
		copy(m.Sequence[:], p[2:8])
		copy(m.Serial[:], p[8:14])
		m.Encrypted = clone(p[16 : len(p)-MACLen])
		copy(m.MAC[:], p[len(p)-MACLen:])
		return m, nil
	case SessionRequestType:
		h, rest, err := ParseHPAI(p)
		if err != nil {
			return nil, err
		}
		if len(rest) != 32 {
			return nil, malformed("%s: public key of %d octets", t, len(rest))
		}
		m := &SessionRequest{Control: h}
		copy(m.PublicKey[:], rest)
		return m, nil
	case SessionResponseType:
		if len(p) != 2+32+MACLen {
			return nil, malformed("%s: body of %d octets, want 50", t, len(p))
		}
		m := &SessionResponse{SessionID: binary.BigEndian.Uint16(p)}
		copy(m.PublicKey[:], p[2:34])
		copy(m.MAC[:], p[34:])
		return m, nil
	case SessionAuthenticateType:
		if len(p) != 2+MACLen {
			return nil, malformed("%s: body of %d octets, want 18", t, len(p))
		}
		m := &SessionAuthenticate{UserID: p[1]}
		copy(m.MAC[:], p[2:])
		return m, nil
	case SessionStatusType:
		if len(p) != 2 {
			return nil, malformed("%s: body of %d octets, want 2", t, len(p))
		}
		return &SessionStatus{Status: SessionStatusCode(p[0])}, nil
	default: // TimerNotifyType
		if len(p) != 14+MACLen {
			return nil, malformed("%s: body of %d octets, want 30", t, len(p))
		}
		m := &TimerNotify{MessageTag: binary.BigEndian.Uint16(p[12:])}
		copy(m.Timer[:], p[0:6])
		copy(m.Serial[:], p[6:12])
		copy(m.MAC[:], p[14:])
		return m, nil
	}
}

// ReadFrame reads one frame from a stream (KNXnet/IP over TCP): the
// header, then the body its total length announces. Frames longer than
// [MaxFrameLen] are refused before their body is read.
func ReadFrame(r io.Reader) ([]byte, error) {
	var h [HeaderLen]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	hdr, err := ParseHeader(h[:])
	if err != nil {
		return nil, err
	}
	if int(hdr.Length) > MaxFrameLen {
		return nil, malformed("%s: total length %d exceeds %d", hdr.Service, hdr.Length, MaxFrameLen)
	}
	b := make([]byte, hdr.Length)
	copy(b, h[:])
	if _, err := io.ReadFull(r, b[HeaderLen:]); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return b, nil
}
