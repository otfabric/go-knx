// SPDX-License-Identifier: MIT

package knxnetip

import "testing"

var benchTunnelling = &TunnellingRequest{Channel: 0x15, Seq: 0x2a, CEMI: []byte{0x11, 0x00, 0xbc, 0xe0, 0x00, 0x00, 0x0a, 0x03, 0x03, 0x00, 0x80, 0x0c, 0x33}}

func BenchmarkMarshalTunnellingRequest(b *testing.B) {
	buf := make([]byte, 0, 64)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var err error
		if buf, err = Append(buf[:0], benchTunnelling); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseTunnellingRequest(b *testing.B) {
	raw, err := Marshal(benchTunnelling)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	for i := 0; i < b.N; i++ {
		if _, err := Parse(raw); err != nil {
			b.Fatal(err)
		}
	}
}
