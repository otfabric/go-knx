// SPDX-License-Identifier: MIT

package cemi

import "testing"

var benchLData = []byte{0x29, 0x00, 0xbc, 0xe0, 0x11, 0x05, 0x0a, 0x03, 0x03, 0x00, 0x80, 0x0c, 0x33}

func BenchmarkParseLData(b *testing.B) {
	b.ReportAllocs()
	b.SetBytes(int64(len(benchLData)))
	for i := 0; i < b.N; i++ {
		if _, err := Parse(benchLData); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMarshalLData(b *testing.B) {
	f, err := Parse(benchLData)
	if err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, 0, 32)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if buf, err = f.AppendTo(buf[:0]); err != nil {
			b.Fatal(err)
		}
	}
}
