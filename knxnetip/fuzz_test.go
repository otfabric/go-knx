// SPDX-License-Identifier: MIT

package knxnetip

import (
	"bytes"
	"reflect"
	"testing"
)

func addGoldenSeeds(f *testing.F) {
	for _, g := range loadGolden(f) {
		f.Add(mustHex(f, g.Hex))
	}
}

// FuzzParse checks that Parse never panics and that a decoded frame
// encodes to a canonical frame of the same length that decodes to the same
// message (decode→encode→decode stability).
func FuzzParse(f *testing.F) {
	addGoldenSeeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Parse(b)
		if err != nil {
			if m != nil {
				t.Fatalf("message %#v with error %v", m, err)
			}
			return
		}
		out, err := Marshal(m)
		if err != nil {
			t.Fatalf("Marshal of decoded %#v: %v", m, err)
		}
		if len(out) != len(b) {
			t.Fatalf("re-encoded %d octets, decoded %d", len(out), len(b))
		}
		m2, err := Parse(out)
		if err != nil {
			t.Fatalf("Parse of re-encoded % X: %v", out, err)
		}
		if !reflect.DeepEqual(m, m2) {
			t.Fatalf("unstable:\n%#v\n%#v", m, m2)
		}
		out2, _ := Marshal(m2)
		if !bytes.Equal(out, out2) {
			t.Fatalf("encoding not idempotent: % X vs % X", out, out2)
		}
	})
}

// FuzzReadFrame checks that ReadFrame never panics, returns exactly the
// frame its header announces and never more than MaxFrameLen octets.
func FuzzReadFrame(f *testing.F) {
	addGoldenSeeds(f)
	f.Add([]byte{0x06, 0x10, 0x06, 0x01, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		r := bytes.NewReader(b)
		fr, err := ReadFrame(r)
		if err != nil {
			return
		}
		h, err := ParseHeader(fr)
		if err != nil {
			t.Fatalf("ReadFrame returned a frame with a bad header: %v", err)
		}
		if int(h.Length) != len(fr) || len(fr) > MaxFrameLen || !bytes.Equal(fr, b[:len(fr)]) {
			t.Fatalf("frame of %d octets, header length %d", len(fr), h.Length)
		}
		if r.Len() != len(b)-len(fr) {
			t.Fatalf("consumed %d octets for a %d-octet frame", len(b)-r.Len(), len(fr))
		}
		_, _ = Parse(fr)
	})
}
