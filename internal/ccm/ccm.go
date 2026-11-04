// SPDX-License-Identifier: MIT

// Package ccm holds the two halves of the AES-CCM construction that KNX IP
// Secure and KNX Data Secure use with their own block 0 and counter 0
// formats: the CBC-MAC and the CTR encryption.
package ccm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
)

// MaxAD is the largest associated data MAC takes: its length is encoded
// in 2 octets. KNX frames carry far less (a KNXnet/IP frame is at most
// 1024 octets, a cEMI APDU at most 255).
const MaxAD = 0xFEFF

// MAC returns the CBC-MAC of b0 || len(ad) || ad || payload, padded with
// zeros to whole blocks: X_1 = E(B_0), X_i+1 = E(X_i XOR B_i), as in
// RFC 3610 §2.2. b0 must hold 16 octets. It panics when ad exceeds
// MaxAD, which no caller passes.
func MAC(key, b0, ad, payload []byte) [16]byte {
	n := len(ad)
	if n > MaxAD {
		panic("ccm: associated data too long")
	}
	b := make([]byte, 0, 16+2+n+len(payload)+15)
	b = append(b, b0...)
	b = binary.BigEndian.AppendUint16(b, uint16(n))
	b = append(b, ad...)
	b = append(b, payload...)
	if r := len(b) % 16; r != 0 {
		b = append(b, make([]byte, 16-r)...)
	}
	// Chaining by hand is CBC encryption with a zero IV, whose last
	// block is the MAC.
	blk := newBlock(key)
	var x [16]byte
	for i := 0; i < len(b); i += 16 {
		subtle.XORBytes(x[:], x[:], b[i:i+16])
		blk.Encrypt(x[:], x[:])
	}
	return x
}

// CTR applies AES-CTR from ctr0: the first key stream block to mac, the
// following ones to payload. It encrypts and decrypts alike.
func CTR(key, ctr0 []byte, mac [16]byte, payload []byte) (out []byte, macOut [16]byte) {
	s := cipher.NewCTR(newBlock(key), ctr0)
	s.XORKeyStream(macOut[:], mac[:])
	out = make([]byte, len(payload))
	s.XORKeyStream(out, payload)
	return out, macOut
}

// XOR applies the AES-CTR key stream from ctr0 to b. KNX Data Secure
// encrypts its 4-octet MAC and then the payload in one stream.
func XOR(key, ctr0, b []byte) []byte {
	out := make([]byte, len(b))
	cipher.NewCTR(newBlock(key), ctr0).XORKeyStream(out, b)
	return out
}

func newBlock(key []byte) cipher.Block {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic("ccm: " + err.Error()) // callers pass 16-octet keys
	}
	return b
}
