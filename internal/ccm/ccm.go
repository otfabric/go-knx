// SPDX-License-Identifier: MIT

// Package ccm holds the two halves of the AES-CCM construction that KNX IP
// Secure and KNX Data Secure use with their own block 0 and counter 0
// formats: the CBC-MAC and the CTR encryption.
package ccm

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

// MAC returns the CBC-MAC (zero IV) of b0 || len(ad) || ad || payload,
// padded with zeros to whole blocks. b0 must hold 16 octets.
func MAC(key, b0, ad, payload []byte) [16]byte {
	b := make([]byte, 0, 16+2+len(ad)+len(payload)+15)
	b = append(b, b0...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(ad)))
	b = append(b, ad...)
	b = append(b, payload...)
	if r := len(b) % 16; r != 0 {
		b = append(b, make([]byte, 16-r)...)
	}
	cipher.NewCBCEncrypter(newBlock(key), make([]byte, 16)).CryptBlocks(b, b)
	var mac [16]byte
	copy(mac[:], b[len(b)-16:])
	return mac
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
