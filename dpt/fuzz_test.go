// SPDX-License-Identifier: MIT

package dpt

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/otfabric/go-knx"
)

// allTypes returns every registered subtype followed by every main type.
// (The registry is filled by init, after package variables.)
func allTypes() []*Type { return append(All(), Mains()...) }

// FuzzDecode decodes data as the type fuzzTypes[idx]. Decode must not panic;
// a decoded value must encode again (unless it lies outside the range of
// the subtype, which Decode does not check) to octets that decode to the
// same value.
func FuzzDecode(f *testing.F) {
	fuzzTypes := allTypes()
	for i, t := range fuzzTypes {
		f.Add(uint16(i), make([]byte, t.Size()))
		f.Add(uint16(i), bytes.Repeat([]byte{0xFF}, t.Size()))
	}
	f.Add(uint16(0), []byte{})
	f.Fuzz(func(tt *testing.T, idx uint16, data []byte) {
		t := fuzzTypes[int(idx)%len(fuzzTypes)]
		v, err := t.Decode(data)
		if err != nil {
			if !errors.Is(err, knx.ErrInvalidValue) {
				tt.Fatalf("%s: Decode error %v does not match ErrInvalidValue", t, err)
			}
			return
		}
		b, err := t.Encode(v)
		if err != nil {
			if outOfRange(t, v) {
				return
			}
			tt.Fatalf("%s: Decode(% X) = %#v does not encode: %v", t, data, v, err)
		}
		if len(b) != t.Size() {
			tt.Fatalf("%s: encoded %d octets, want %d", t, len(b), t.Size())
		}
		v2, err := t.Decode(b)
		if err != nil {
			tt.Fatalf("%s: re-encoded % X does not decode: %v", t, b, err)
		}
		if !reflect.DeepEqual(v, v2) {
			tt.Fatalf("%s: % X → %#v → % X → %#v", t, data, v, b, v2)
		}
		// Format never panics.
		_ = t.Format(v)
	})
}

// outOfRange reports a decoded number outside the documented range of t.
func outOfRange(t *Type, v any) bool {
	var f float64
	switch x := v.(type) {
	case float64:
		f = x
	case uint64:
		f = float64(x)
	case int64:
		f = float64(x)
	default:
		return false
	}
	return t.HasRange && (f < t.Min || f > t.Max) || math.IsInf(f, 0)
}
