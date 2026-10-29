// SPDX-License-Identifier: MIT

// Package secure implements KNX IP Secure (KNXnet/IP Secure): the key
// derivations, the session handshake of secure tunnelling, the
// SECURE_WRAPPER encryption, and the timer of secure routing.
//
// The implementation follows public sources, not the KNX application note
// 159 (see docs/standards/SPECIFICATIONS.md, "KNX Secure sources"); it is
// verified against the AN159 example frames quoted by xknx and by
// interoperability with xknx and Calimero.
package secure

import (
	"crypto/sha256"
	"fmt"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/internal/pbkdf2"
)

// Key is an AES-128 key: a session key, backbone key, user password key
// or device authentication code.
type Key [16]byte

// Salts and iteration count of the PBKDF2-HMAC-SHA256 password
// derivations.
const (
	saltDeviceAuth = "device-authentication-code.1.secure.ip.knx.org"
	saltUser       = "user-password.1.secure.ip.knx.org"
	kdfIterations  = 65536
)

// DeviceAuthenticationCode derives the device authentication code from
// the device authentication password. Passwords are Latin-1 text.
func DeviceAuthenticationCode(password string) (Key, error) {
	return derive(password, saltDeviceAuth)
}

// UserPasswordKey derives the password key of a user from the password.
func UserPasswordKey(password string) (Key, error) {
	return derive(password, saltUser)
}

func derive(password, salt string) (Key, error) {
	pw, err := latin1(password)
	if err != nil {
		return Key{}, err
	}
	var k Key
	copy(k[:], pbkdf2.SHA256(pw, []byte(salt), kdfIterations, len(k)))
	return k, nil
}

// latin1 encodes s as ISO 8859-1.
func latin1(s string) ([]byte, error) {
	b := make([]byte, 0, len(s))
	for _, r := range s {
		if r > 0xFF {
			return nil, fmt.Errorf("%w: secure: password character %q is not Latin-1", knx.ErrInvalidValue, r)
		}
		b = append(b, byte(r))
	}
	return b, nil
}

// SessionKey derives the session key from the X25519 shared secret: the
// first 16 octets of its SHA-256 hash.
func SessionKey(shared []byte) Key {
	h := sha256.Sum256(shared)
	var k Key
	copy(k[:], h[:16])
	return k
}
