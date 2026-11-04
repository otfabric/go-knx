// SPDX-License-Identifier: MIT

package ccm

import (
	"crypto/cipher"
	"encoding/binary"
	"testing"
)

// cbcMAC is the reference: the last block of CBC encryption with a zero
// IV of the same padded input.
func cbcMAC(key, b0, ad, payload []byte) [16]byte {
	b := append(append([]byte(nil), b0...), 0, 0)
	binary.BigEndian.PutUint16(b[16:], uint16(len(ad)))
	b = append(append(b, ad...), payload...)
	if r := len(b) % 16; r != 0 {
		b = append(b, make([]byte, 16-r)...)
	}
	cipher.NewCBCEncrypter(newBlock(key), make([]byte, 16)).CryptBlocks(b, b)
	var m [16]byte
	copy(m[:], b[len(b)-16:])
	return m
}

func TestMACMatchesCBC(t *testing.T) {
	key := make([]byte, 16)
	b0 := make([]byte, 16)
	for i := range key {
		key[i], b0[i] = byte(i), byte(0xF0-i)
	}
	for _, n := range [][2]int{{0, 0}, {1, 0}, {14, 0}, {15, 1}, {30, 17}, {2, 64}, {0, 33}, {300, 1000}} {
		ad, payload := make([]byte, n[0]), make([]byte, n[1])
		for i := range ad {
			ad[i] = byte(i * 7)
		}
		for i := range payload {
			payload[i] = byte(i * 13)
		}
		if got, want := MAC(key, b0, ad, payload), cbcMAC(key, b0, ad, payload); got != want {
			t.Errorf("ad %d payload %d: MAC %x, CBC-MAC %x", n[0], n[1], got, want)
		}
	}
}

func TestMACADTooLong(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("MAC with associated data beyond MaxAD did not panic")
		}
	}()
	MAC(make([]byte, 16), make([]byte, 16), make([]byte, MaxAD+1), nil)
}
