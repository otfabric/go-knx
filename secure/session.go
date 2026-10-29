// SPDX-License-Identifier: MIT

package secure

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/internal/ccm"
	"github.com/otfabric/go-knx/knxnetip"
)

// handshakeCtr0 is counter 0 of the SESSION_RESPONSE and
// SESSION_AUTHENTICATE MACs.
var handshakeCtr0 = []byte{14: 0xFF, 15: 0x00}

// KeyPair is an X25519 key pair of the session handshake.
type KeyPair struct {
	priv *ecdh.PrivateKey
	// Public is the public key sent in SESSION_REQUEST or
	// SESSION_RESPONSE.
	Public [32]byte
}

// NewKeyPair generates a key pair.
func NewKeyPair() (*KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	kp := &KeyPair{priv: priv}
	copy(kp.Public[:], priv.PublicKey().Bytes())
	return kp, nil
}

// SessionKey derives the session key with the peer's public key.
func (kp *KeyPair) SessionKey(peer [32]byte) (Key, error) {
	pub, err := ecdh.X25519().NewPublicKey(peer[:])
	if err != nil {
		return Key{}, fmt.Errorf("%w: secure: public key: %v", knx.ErrSecurity, err)
	}
	shared, err := kp.priv.ECDH(pub)
	if err != nil {
		return Key{}, fmt.Errorf("%w: secure: key agreement: %v", knx.ErrSecurity, err)
	}
	return SessionKey(shared), nil
}

func xorKeys(a, b [32]byte) (x [32]byte) {
	for i := range x {
		x[i] = a[i] ^ b[i]
	}
	return x
}

func handshakeMAC(key Key, ad []byte) [16]byte {
	mac := ccm.MAC(key[:], make([]byte, 16), ad, nil)
	_, enc := ccm.CTR(key[:], handshakeCtr0, mac, nil)
	return enc
}

// ResponseMAC returns the MAC of a SESSION_RESPONSE under the device
// authentication code.
func ResponseMAC(device Key, session uint16, client, server [32]byte) [16]byte {
	ad := knxnetip.AppendHeader(make([]byte, 0, 40), knxnetip.SessionResponseType, 2+32+knxnetip.MACLen)
	ad = binary.BigEndian.AppendUint16(ad, session)
	x := xorKeys(client, server)
	return handshakeMAC(device, append(ad, x[:]...))
}

// AuthenticateMAC returns the MAC of a SESSION_AUTHENTICATE under the
// user's password key.
func AuthenticateMAC(user Key, userID uint8, client, server [32]byte) [16]byte {
	ad := knxnetip.AppendHeader(make([]byte, 0, 40), knxnetip.SessionAuthenticateType, 2+knxnetip.MACLen)
	ad = append(ad, 0, userID)
	x := xorKeys(client, server)
	return handshakeMAC(user, append(ad, x[:]...))
}

// Equal compares two MACs in constant time.
func Equal(a, b [16]byte) bool { return subtle.ConstantTimeCompare(a[:], b[:]) == 1 }

// Session is the state of an established secure session (tunnelling
// over a unicast connection): the session key and the sequence counters
// of both directions. It is safe for concurrent use.
type Session struct {
	ID     uint16
	key    Key
	serial [6]byte

	mu     sync.Mutex
	tx     uint64
	rx     uint64
	rxSeen bool
}

// NewSession returns a session with identifier id and the session key;
// serial is the KNX serial number sent in its wrappers.
func NewSession(id uint16, key Key, serial [6]byte) *Session {
	return &Session{ID: id, key: key, serial: serial}
}

// Wrap seals a frame with the next sequence number.
func (s *Session) Wrap(frame []byte) (*knxnetip.SecureWrapper, error) {
	s.mu.Lock()
	seq := s.tx
	if seq > MaxSequence {
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: secure: session sequence exhausted", knx.ErrSecurity)
	}
	s.tx++
	s.mu.Unlock()
	// Tunnelling uses message tag 0.
	return Seal(s.key, s.ID, seq, s.serial, 0, frame)
}

// Marshal wraps a message and encodes the SECURE_WRAPPER.
func (s *Session) Marshal(m knxnetip.Message) ([]byte, error) {
	b, err := knxnetip.Marshal(m)
	if err != nil {
		return nil, err
	}
	w, err := s.Wrap(b)
	if err != nil {
		return nil, err
	}
	return knxnetip.Marshal(w)
}

// Unwrap verifies a SECURE_WRAPPER of the session and returns its frame.
// Sequence numbers must increase: a repeated or older one is a replay.
func (s *Session) Unwrap(w *knxnetip.SecureWrapper) ([]byte, error) {
	if w.SessionID != s.ID {
		return nil, fmt.Errorf("%w: secure: session %d, want %d", knx.ErrSecurity, w.SessionID, s.ID)
	}
	seq := Uint48(w.Sequence)
	s.mu.Lock()
	replay := s.rxSeen && seq <= s.rx
	s.mu.Unlock()
	if replay {
		return nil, fmt.Errorf("%w: secure: sequence %d replayed", knx.ErrSecurity, seq)
	}
	frame, err := Open(s.key, w)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rxSeen && seq <= s.rx {
		return nil, fmt.Errorf("%w: secure: sequence %d replayed", knx.ErrSecurity, seq)
	}
	s.rx, s.rxSeen = seq, true
	return frame, nil
}

// Credentials identify a secure tunnelling user to a server.
type Credentials struct {
	// UserID is the user (1 is the management user; tunnelling users
	// start at 2).
	UserID uint8
	// UserKey is the user's password key.
	UserKey Key
	// DeviceCode is the device authentication code of the server. When
	// set, the client verifies the server's SESSION_RESPONSE with it; nil
	// skips that check.
	DeviceCode *Key
}

// NewCredentials derives the credentials of a user from the passwords;
// an empty device password leaves DeviceCode nil.
func NewCredentials(userID uint8, userPassword, devicePassword string) (Credentials, error) {
	c := Credentials{UserID: userID}
	var err error
	if c.UserKey, err = UserPasswordKey(userPassword); err != nil {
		return c, err
	}
	if devicePassword != "" {
		d, err := DeviceAuthenticationCode(devicePassword)
		if err != nil {
			return c, err
		}
		c.DeviceCode = &d
	}
	return c, nil
}
