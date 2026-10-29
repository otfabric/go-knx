// SPDX-License-Identifier: MIT

package cemi

import (
	"bytes"
	"reflect"
	"testing"
)

// FuzzParse checks that Parse never panics and that every decoded frame
// encodes back to the octets it was decoded from (cEMI has no reserved
// fields this package drops) and decodes to the same frame again.
func FuzzParse(f *testing.F) {
	for _, g := range goldenCEMI {
		f.Add(h(f, g.hex))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		fr, err := Parse(b)
		if err != nil {
			if fr != nil {
				t.Fatalf("frame with error %v", err)
			}
			return
		}
		out, err := Marshal(fr)
		if err != nil {
			t.Fatalf("Marshal of decoded %#v: %v", fr, err)
		}
		if !bytes.Equal(out, b) {
			t.Fatalf("decode→encode:\n got % X\nwant % X", out, b)
		}
		fr2, err := Parse(out)
		if err != nil || !reflect.DeepEqual(fr, fr2) {
			t.Fatalf("unstable: %#v %#v %v", fr, fr2, err)
		}
	})
}
