// SPDX-License-Identifier: MIT

// Package pbkdf2 implements PBKDF2 (RFC 8018) with HMAC-SHA256: the key
// derivation of KNX IP Secure passwords and of keyrings. The standard
// library has crypto/pbkdf2 since Go 1.24; this package dates from when
// go-knx built with Go 1.23 and is kept as it is.
package pbkdf2

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

// SHA256 derives a key of keyLen octets from password and salt.
func SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	n := (keyLen + prf.Size() - 1) / prf.Size()
	out := make([]byte, 0, n*prf.Size())
	var ctr [4]byte
	for block := 1; block <= n; block++ {
		binary.BigEndian.PutUint32(ctr[:], uint32(block))
		u := sum(prf, salt, ctr[:])
		t := append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
			u = sum(prf, u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

func sum(h hash.Hash, parts ...[]byte) []byte {
	h.Reset()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}
