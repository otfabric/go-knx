// SPDX-License-Identifier: MIT

package dpt

import "testing"

func BenchmarkDPT9Encode(b *testing.B) {
	t := MustLookup("9.001")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := t.Encode(21.5); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDPT9Decode(b *testing.B) {
	t := MustLookup("9.001")
	data := []byte{0x0c, 0x33}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := t.Decode(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeFloat16(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := EncodeFloat16(-30); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLookup(b *testing.B) {
	for _, id := range []string{"9.001", "DPST-9-1", "9"} {
		b.Run(id, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := Lookup(id); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
