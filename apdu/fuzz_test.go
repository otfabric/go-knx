// SPDX-License-Identifier: MIT

package apdu

import (
	"bytes"
	"reflect"
	"testing"
)

var fuzzSeeds = [][]byte{
	{0x00, 0x00}, {0x00, 0x81}, {0x00, 0x40, 0x0c, 0x33}, {0x42, 0x03, 0x01, 0x00}, {0x4B, 0xD5, 0x00, 0x0b, 0x10, 0x01},
	{0x01, 0xC5, 0xAA}, {0x01, 0xC8}, {0x04, 0x80, 0x01}, {0x80}, {0x81}, {0xCE}, {0xC3}, {0x03, 0xF1, 0x00},
}

// FuzzParse checks that Parse never panics and that a decoded TPDU encodes
// back to exactly its input.
func FuzzParse(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Parse(b)
		if err != nil {
			return
		}
		if out := p.Bytes(); !bytes.Equal(out, b) {
			t.Fatalf("Parse(% X) = %+v encodes to % X", b, p, out)
		}
	})
}

// FuzzParseGroupValue checks that ParseGroupValue never panics and that a
// decoded group value of a TPDU that fits a frame encodes to a TPDU that
// decodes to the same service and value.
func FuzzParseGroupValue(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		svc, v, err := ParseGroupValue(b)
		if err != nil || len(b) > 256 {
			return
		}
		var out []byte
		switch svc {
		case GroupValueReadService:
			out = GroupValueRead()
		case GroupValueWriteService:
			out, err = GroupValueWrite(v)
		case GroupValueResponseService:
			out, err = GroupValueResponse(v)
		default:
			t.Fatalf("service %s", svc)
		}
		if err != nil {
			t.Fatalf("re-encode %s %+v: %v", svc, v, err)
		}
		svc2, v2, err := ParseGroupValue(out)
		if err != nil || svc2 != svc || !reflect.DeepEqual(v, v2) {
			t.Fatalf("unstable: % X → %s %+v → % X → %s %+v %v", b, svc, v, out, svc2, v2, err)
		}
	})
}
