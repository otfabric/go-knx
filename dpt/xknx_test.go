// SPDX-License-Identifier: MIT

package dpt

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
)

// The vectors of testdata/xknx_vectors.json were produced by xknx 4.0.0
// (see the _note in the file). They cross-check the encodings of this
// package against an independent, widely deployed implementation. Known,
// deliberate differences:
//
//   - DPT 9 rounding: xknx rounds the mantissa half to even (Python's
//     round), this package half away from zero; 0.125 is 0x000C there and
//     0x000D here. Both decode within the resolution of the type.
//   - DPT 9 ranges: the vectors check the 2-octet float format, so they are
//     encoded with the main type "9" (whose range is the whole format);
//     xknx does not apply the subtype limits of the standard.
//   - DPT 17 and 18: xknx presents scene numbers 1..64 (as ETS does), this
//     package the raw 0..63.
//   - DPT 14 decoding: xknx rounds to 7 significant digits; the values are
//     compared as float32.

type xknxVector struct {
	DPT   string          `json:"dpt"`
	Value json.RawMessage `json:"value"`
	Hex   string          `json:"hex"`
	Error string          `json:"error"`
}

func loadXKNX(t *testing.T) (encode, decode []xknxVector) {
	raw, err := os.ReadFile("testdata/xknx_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Encode []xknxVector `json:"encode"`
		Decode []xknxVector `json:"decode"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Encode) < 50 || len(f.Decode) < 20 {
		t.Fatalf("%d encode and %d decode vectors", len(f.Encode), len(f.Decode))
	}
	return f.Encode, f.Decode
}

// goValue converts a JSON value of the vectors to the input this package
// takes for the type.
func goValue(t *testing.T, ty *Type, raw json.RawMessage) any {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	if n, ok := v.(json.Number); ok {
		if ty.Kind == KindSigned || ty.Kind == KindUnsigned || ty.Kind == KindEnum || ty.Kind == KindScene {
			i, err := n.Int64()
			if err != nil {
				t.Fatalf("%s: %v", ty, err)
			}
			if ty.Kind == KindEnum {
				return Enum{Value: uint8(i)}
			}
			return i
		}
		f, _ := n.Float64()
		return f
	}
	return v
}

func TestXKNXEncode(t *testing.T) {
	enc, _ := loadXKNX(t)
	for _, v := range enc {
		id := v.DPT
		if strings.HasPrefix(id, "9.") {
			id = "9"
		}
		ty := MustLookup(id)
		in := goValue(t, ty, v.Value)
		want := v.Hex
		switch {
		case ty.ID.Main == 9 && v.Error == "" && isTie(in.(float64)):
			// Half away from zero here, half to even in xknx: one
			// mantissa step apart.
			x, _ := hex.DecodeString(v.Hex)
			raw := uint16(x[0])<<8 | uint16(x[1])
			want = hex.EncodeToString([]byte{byte((raw + 1) >> 8), byte(raw + 1)})
		case ty.ID.Main == 17:
			// xknx scene n is raw n-1.
			in = in.(int64) - 1
			if v.Error != "" { // xknx refuses scene 0, which is raw -1
				_, err := ty.Encode(in)
				wantInvalid(t, "scene -1", err)
				continue
			}
		}
		b, err := ty.Encode(in)
		if v.Error != "" {
			if err == nil {
				t.Errorf("%s Encode(%v) = % X; xknx: %s", v.DPT, in, b, v.Error)
			}
			continue
		}
		if err != nil || hex.EncodeToString(b) != want {
			t.Errorf("%s Encode(%v) = %x, %v; xknx %s", v.DPT, in, b, err, v.Hex)
		}
	}
}

func TestXKNXDecode(t *testing.T) {
	_, decs := loadXKNX(t)
	for _, v := range decs {
		ty := MustLookup(v.DPT)
		b, err := hex.DecodeString(v.Hex)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ty.Decode(b)
		if v.Error != "" {
			if err == nil {
				t.Errorf("%s Decode(%s) = %v; xknx: %s", v.DPT, v.Hex, got, v.Error)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s Decode(%s): %v", v.DPT, v.Hex, err)
			continue
		}
		var want any
		if err := json.Unmarshal(v.Value, &want); err != nil {
			t.Fatal(err)
		}
		ok := false
		switch g := got.(type) {
		case float64:
			w := want.(float64)
			if ty.ID.Main == 14 {
				ok = float32(g) == float32(w) || math.Abs(g-w) <= math.Abs(w)*1e-6
			} else {
				ok = g == w
			}
		case TimeOfDay:
			m := want.(map[string]any)
			days := map[string]uint8{"no_day": 0, "monday": 1, "tuesday": 2, "wednesday": 3, "thursday": 4, "friday": 5, "saturday": 6, "sunday": 7}
			ok = float64(g.Hour) == m["hour"] && float64(g.Minute) == m["minutes"] && float64(g.Second) == m["seconds"] && g.Weekday == days[m["day"].(string)]
		case Date:
			m := want.(map[string]any)
			ok = float64(g.Year) == m["year"] && float64(g.Month) == m["month"] && float64(g.Day) == m["day"]
		case SceneControl:
			m := want.(map[string]any)
			ok = float64(g.Scene)+1 == m["scene_number"] && g.Learn == m["learn"]
		default:
			t.Fatalf("%s: unexpected %T", v.DPT, got)
		}
		if !ok {
			t.Errorf("%s Decode(%s) = %#v; xknx %s", v.DPT, v.Hex, got, v.Value)
		}
	}
}

// isTie reports a DPT 9 value whose mantissa lies exactly halfway between
// two integers at the exponent the encoder picks.
func isTie(f float64) bool {
	v := f * 100
	for e := 0; e <= 15; e++ {
		x := v / math.Ldexp(1, e)
		if m := math.Round(x); m >= -2048 && m <= 2047 {
			return x > 0 && x-math.Floor(x) == 0.5 && int64(math.Floor(x))%2 == 0
		}
	}
	return false
}

func TestXKNXVectorsCoverRounding(t *testing.T) {
	// Guard against a vector file that silently lost the DPT 9 rounding
	// cases this package documents.
	enc, _ := loadXKNX(t)
	seen := map[float64]bool{}
	for _, v := range enc {
		if v.DPT == "9.001" {
			var f float64
			_ = json.Unmarshal(v.Value, &f)
			seen[f] = true
		}
	}
	for _, f := range []float64{21.5, -30, 0.01, 670433.28, 0.125, 20.48, -20.48} {
		if !seen[f] {
			t.Errorf("no xknx vector for 9.001 %v", f)
		}
	}
}
