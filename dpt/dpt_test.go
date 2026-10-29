// SPDX-License-Identifier: MIT

package dpt

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/otfabric/go-knx"
)

func hx(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

func enc(t *testing.T, id string, v any) []byte {
	t.Helper()
	b, err := MustLookup(id).Encode(v)
	if err != nil {
		t.Fatalf("%s Encode(%#v): %v", id, v, err)
	}
	return b
}

func dec(t *testing.T, id string, b []byte) any {
	t.Helper()
	v, err := MustLookup(id).Decode(b)
	if err != nil {
		t.Fatalf("%s Decode(% X): %v", id, b, err)
	}
	return v
}

func wantInvalid(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, knx.ErrInvalidValue) {
		t.Errorf("%s: %v, want ErrInvalidValue", what, err)
	}
}

// goType is the Go type of decoded values of each kind.
var goType = map[Kind]reflect.Type{
	KindBool: reflect.TypeOf(false), KindControl: reflect.TypeOf(Control{}), KindStep: reflect.TypeOf(Step{}),
	KindChar: reflect.TypeOf(""), KindUnsigned: reflect.TypeOf(uint64(0)), KindSigned: reflect.TypeOf(int64(0)),
	KindFloat: reflect.TypeOf(0.0), KindTime: reflect.TypeOf(TimeOfDay{}), KindDate: reflect.TypeOf(Date{}),
	KindString: reflect.TypeOf(""), KindScene: reflect.TypeOf(uint8(0)), KindSceneControl: reflect.TypeOf(SceneControl{}),
	KindDateTime: reflect.TypeOf(DateTime{}), KindEnum: reflect.TypeOf(Enum{}), KindBits: reflect.TypeOf(uint64(0)),
	KindRGB: reflect.TypeOf(RGB{}), KindRGBW: reflect.TypeOf(RGBW{}), KindXYY: reflect.TypeOf(XYY{}),
}

// samples returns values of t that must survive an encode/decode round
// trip (exactly, or within the resolution of the type for floats).
func samples(t *Type) []any {
	switch t.Kind {
	case KindBool:
		return []any{false, true}
	case KindControl:
		return []any{Control{}, Control{Control: true}, Control{Value: true}, Control{Control: true, Value: true}}
	case KindStep:
		return []any{Step{}, Step{Increase: true, StepCode: 7}, Step{StepCode: 1}}
	case KindChar:
		if t.ID.Sub == 1 {
			return []any{"", "A", "~"}
		}
		return []any{"", "A", "é", "ÿ"}
	case KindUnsigned:
		max := math.Ldexp(1, t.Bits) - 1
		if t.HasRange {
			max = t.Max
		}
		return []any{uint64(0), uint64(1), uint64(max)}
	case KindSigned:
		lo, hi := -math.Ldexp(1, t.Bits-1), math.Ldexp(1, t.Bits-1)-1
		if t.Bits == 64 {
			return []any{int64(math.MinInt64), int64(-1), int64(0), int64(math.MaxInt64)}
		}
		return []any{int64(lo), int64(-1), int64(0), int64(hi)}
	case KindFloat:
		switch t.ID.Main {
		case 9:
			v := []any{0.0, 21.5, t.Max}
			if t.Min < 0 {
				v = append(v, -30.0)
			}
			if t.Min <= Float16Min {
				v = append(v, Float16Min)
			}
			return v
		case 14:
			return []any{0.0, 1.5, -0.1, 3.4028235e38, -1e-45}
		case 5:
			return []any{0.0, t.Max / 2, t.Max}
		case 7:
			s := scaleOf(t)
			return []any{0.0, s, 65535 * s}
		case 8, 13:
			s := scaleOf(t)
			bits := float64(t.Bits)
			return []any{-math.Exp2(bits-1) * s, 0.0, s, (math.Exp2(bits-1) - 1) * s}
		}
	case KindTime:
		return []any{TimeOfDay{}, TimeOfDay{Weekday: 7, Hour: 23, Minute: 59, Second: 59}, TimeOfDay{Weekday: 1, Hour: 12, Minute: 30, Second: 5}}
	case KindDate:
		return []any{Date{1990, 1, 1}, Date{1999, 12, 31}, Date{2000, 1, 1}, Date{2026, 10, 29}, Date{2089, 12, 31}}
	case KindString:
		v := []any{"", "KNX is OK", "abcdefghijklmn"}
		if t.ID.Sub == 1 {
			v = append(v, "Grüße ÿ")
		}
		return v
	case KindScene:
		return []any{uint8(0), uint8(63)}
	case KindSceneControl:
		return []any{SceneControl{}, SceneControl{Learn: true, Scene: 63}}
	case KindDateTime:
		return []any{
			DateTime{Year: 2026, Month: 10, Day: 29, Weekday: 4, Hour: 12, Minute: 30, Second: 5, WorkingDay: true, SummerTime: true, ExternalSync: true},
			DateTime{Year: 1900, Month: 1, Day: 1, Hour: 24, Fault: true, NoWorkingDay: true, NoYear: true, NoWeekday: true, ReliableSource: true},
			DateTime{Year: 2155, Month: 12, Day: 31, Weekday: 7, Hour: 23, Minute: 59, Second: 59},
			DateTime{Year: 2000, NoDate: true, NoTime: true, Hour: 31, Minute: 63, Second: 63},
		}
	case KindEnum:
		if t.Enum == nil {
			return []any{Enum{}, Enum{Value: 255}}
		}
		var v []any
		for k, n := range t.Enum {
			v = append(v, Enum{Value: k, Name: n})
		}
		return v
	case KindBits:
		return []any{uint64(0), uint64(5), uint64(1)<<t.Bits - 1}
	case KindRGB:
		return []any{RGB{}, RGB{0xFF, 0x80, 0x01}}
	case KindRGBW:
		return []any{RGBW{}, RGBW{R: 1, G: 2, B: 3, W: 4, ValidR: true, ValidW: true}, RGBW{R: 255, G: 255, B: 255, W: 255, ValidR: true, ValidG: true, ValidB: true, ValidW: true}}
	case KindXYY:
		return []any{XYY{}, XYY{X: 1, Y: 1, Brightness: 100, ColorValid: true, BrightnessValid: true}, XYY{X: 0.2, Y: 0.6, Brightness: 20, ColorValid: true}}
	}
	return nil
}

// scaleOf returns the resolution of a scaled integer subtype.
func scaleOf(t *Type) float64 {
	v, _ := t.Decode([]byte{0, 0, 0, 1}[4-t.Size():])
	if f, ok := v.(float64); ok {
		return f
	}
	return 1
}

func approxEqual(t *Type, a, b float64) bool {
	switch t.ID.Main {
	case 9:
		return math.Abs(a-b) <= math.Max(0.005, math.Abs(a)/2000)
	case 5:
		return math.Abs(a-b) <= t.Max/255/2+1e-9
	}
	return a == b
}

func TestRegistryConsistency(t *testing.T) {
	all := All()
	if len(all) < 200 {
		t.Fatalf("only %d registered subtypes", len(all))
	}
	for i, ty := range all {
		if i > 0 {
			p := all[i-1].ID
			if p.Main > ty.ID.Main || p.Main == ty.ID.Main && p.Sub >= ty.ID.Sub {
				t.Fatalf("All() not ordered at %s, %s", p, ty.ID)
			}
		}
		if _, ok := mains[ty.ID.Main]; !ok {
			t.Errorf("%s has no main type", ty)
		}
		if got, err := Lookup(ty.ID.String()); err != nil || got != ty {
			t.Errorf("Lookup(%q) = %v, %v", ty.ID, got, err)
		}
		if got, ok := Get(ty.ID); !ok || got != ty {
			t.Errorf("Get(%v) = %v %v", ty.ID, got, ok)
		}
		if ty.Name == "" || ty.Description == "" || ty.Bits <= 0 {
			t.Errorf("%s: incomplete %+v", ty.ID, ty)
		}
		if ty.Kind == KindBool && len(ty.Labels) != 2 {
			t.Errorf("%s: %d labels", ty, len(ty.Labels))
		}
	}
	ms := Mains()
	for i, m := range ms {
		if i > 0 && ms[i-1].ID.Main >= m.ID.Main {
			t.Fatal("Mains() not ordered")
		}
		if m.ID.Sub != 0 {
			t.Errorf("main %s has a subtype", m.ID)
		}
		if got, err := Lookup(fmtMain(m.ID.Main)); err != nil || got != m {
			t.Errorf("Lookup main %d = %v, %v", m.ID.Main, got, err)
		}
	}
}

func fmtMain(m uint16) string { return ID{Main: m}.String()[:len(ID{Main: m}.String())-4] }

func TestSmallAndSize(t *testing.T) {
	cases := []struct {
		id    string
		small bool
		size  int
	}{
		{"1.001", true, 1}, {"2.001", true, 1}, {"3.007", true, 1}, {"4.001", false, 1}, {"5.001", false, 1},
		{"7.001", false, 2}, {"9.001", false, 2}, {"10.001", false, 3}, {"11.001", false, 3}, {"12.001", false, 4},
		{"14.056", false, 4}, {"16.000", false, 14}, {"19.001", false, 8}, {"29.010", false, 8},
		{"232.600", false, 3}, {"242.600", false, 6}, {"251.600", false, 6},
	}
	for _, c := range cases {
		ty := MustLookup(c.id)
		if ty.Small() != c.small || ty.Size() != c.size {
			t.Errorf("%s: Small %v Size %d", c.id, ty.Small(), ty.Size())
		}
	}
	for _, ty := range append(All(), Mains()...) {
		if ty.Small() != (ty.Bits <= 6) || ty.Size() != (ty.Bits+7)/8 {
			t.Errorf("%s: Small %v Size %d for %d bits", ty, ty.Small(), ty.Size(), ty.Bits)
		}
	}
}

// TestEveryTypeRoundTrip encodes sample values of every registered subtype
// and main type, checks the size and decodes them back.
func TestEveryTypeRoundTrip(t *testing.T) {
	for _, ty := range append(All(), Mains()...) {
		ss := samples(ty)
		if len(ss) == 0 {
			t.Errorf("%s: no samples", ty)
			continue
		}
		for _, v := range ss {
			b, err := ty.Encode(v)
			if err != nil {
				t.Errorf("%s Encode(%#v): %v", ty, v, err)
				continue
			}
			if len(b) != ty.Size() {
				t.Errorf("%s Encode(%#v) = % X, want %d octets", ty, v, b, ty.Size())
			}
			got, err := ty.Decode(b)
			if err != nil {
				t.Errorf("%s Decode(% X): %v", ty, b, err)
				continue
			}
			if reflect.TypeOf(got) != goType[ty.Kind] {
				t.Errorf("%s decodes to %T, want %v for %s", ty, got, goType[ty.Kind], ty.Kind)
			}
			if f, ok := v.(float64); ok {
				if g := got.(float64); !approxEqual(ty, f, g) {
					t.Errorf("%s: %v → % X → %v", ty, f, b, g)
				}
				continue
			}
			if !reflect.DeepEqual(got, v) {
				t.Errorf("%s: %#v → % X → %#v", ty, v, b, got)
			}
		}
	}
}

// TestExhaustiveSmallTypes decodes every value of every 1- and 2-octet
// type (except DPT 9, whose encoding is canonicalised) and checks that a
// decoded value encodes to the octets it came from.
func TestExhaustiveSmallTypes(t *testing.T) {
	for _, ty := range append(All(), Mains()...) {
		if ty.Size() > 2 || ty.ID.Main == 9 {
			continue
		}
		n, ok := 1<<ty.Bits, 0
		if ty.Bits > 16 {
			n = 1 << 16
		}
		for raw := 0; raw < n; raw++ {
			b := []byte{byte(raw)}
			if ty.Size() == 2 {
				b = []byte{byte(raw >> 8), byte(raw)}
			}
			v, err := ty.Decode(b)
			if err != nil {
				wantInvalid(t, ty.String(), err)
				continue
			}
			ok++
			out, err := ty.Encode(v)
			if err != nil && (!ty.HasRange || ty.Kind != KindUnsigned) {
				t.Fatalf("%s: % X → %#v: %v", ty, b, v, err)
			}
			if err == nil && !bytes.Equal(out, b) {
				t.Fatalf("%s: % X → %#v → % X", ty, b, v, out)
			}
		}
		if ok == 0 {
			t.Errorf("%s: no value decodes", ty)
		}
	}
}

func TestDecodeErrors(t *testing.T) {
	cases := []struct {
		id  string
		hex string
	}{
		{"9.001", ""}, {"9.001", "00"}, {"9.001", "000000"}, {"1.001", ""}, {"1.001", "0000"},
		{"1.001", "02"}, {"2.001", "04"}, {"3.007", "10"}, // more bits than the type
		{"9.001", "7fff"},
		{"14.056", "7f800000"}, {"14.056", "ff800000"}, {"14.056", "7fc00000"},
		{"10.001", "180000"}, {"10.001", "173c00"}, {"10.001", "17003c"}, {"10.001", "174000"},
		{"11.001", "000a1a"}, {"11.001", "200a1a"}, {"11.001", "1d001a"}, {"11.001", "1d0d1a"}, {"11.001", "1d1a1a"}, {"11.001", "1d0a64"},
		{"16.000", "e9000000000000000000000000000000"[:28]}, {"16.000", "4100410000000000000000000000"}, {"4.001", "80"},
		{"17.001", "40"}, {"18.001", "40"},
		{"19.001", "7e1a1d8c1e050000"}, {"19.001", "7e0a3d8c1e050000"}, {"19.001", "7e0a1d8c5e050000"}, {"19.001", "7e0a1d8c1e450000"},
		{"19.001", "7e001d8c1e050000"}, {"19.001", "7e0a008c1e050000"}, {"19.001", "7e0a1d991e050000"},
		{"19.001", "7e0a1d183b000000"}, {"19.001", "7e0a1d18003b0000"}, {"19.001", "7e0a1d183c000000"},
		{"20.102", "05"}, {"251.600", "010203040100"}, {"251.600", "010203040010"}, {"242.600", "000000000004"},
	}
	for _, c := range cases {
		v, err := MustLookup(c.id).Decode(hx(c.hex))
		if v != nil {
			t.Errorf("%s Decode(%s) returned %#v with %v", c.id, c.hex, v, err)
		}
		wantInvalid(t, c.id+" "+c.hex, err)
		if err != nil && !strings.Contains(err.Error(), "dpt "+c.id) {
			t.Errorf("error %q does not name the type", err)
		}
	}
	if _, err := MustLookup("9.001").Decode(hx("7fff")); !errors.Is(err, ErrFloat16Invalid) {
		t.Errorf("0x7FFF: %v, want ErrFloat16Invalid", err)
	}
}

func TestEncodeWrongType(t *testing.T) {
	for id, v := range map[string]any{
		"1.001": "on", "2.001": true, "3.007": 3, "4.001": 'A', "5.001": "50", "5.010": "1", "6.001": 1.5,
		"7.001": -1, "9.001": "21", "10.001": "12:00", "11.001": "2026-01-01", "14.056": true, "16.000": 5,
		"17.001": "1", "18.001": 1, "19.001": Date{}, "20.102": 1.5, "21.001": "x", "232.600": "#FFFFFF",
		"242.600": RGB{}, "251.600": RGB{},
	} {
		b, err := MustLookup(id).Encode(v)
		if b != nil {
			t.Errorf("%s Encode(%#v) = % X", id, v, b)
		}
		wantInvalid(t, id, err)
	}
}

func TestDPT1(t *testing.T) {
	for _, c := range []struct {
		v    any
		want byte
	}{{true, 1}, {false, 0}, {1, 1}, {0, 0}, {uint8(1), 1}, {uint8(0), 0}} {
		if b := enc(t, "1.001", c.v); !bytes.Equal(b, []byte{c.want}) {
			t.Errorf("Encode(%#v) = % X", c.v, b)
		}
	}
	for _, v := range []any{2, -1, uint8(2), int64(1)} {
		_, err := MustLookup("1.001").Encode(v)
		wantInvalid(t, "1.001", err)
	}
	sw := MustLookup("1.001")
	if sw.Format(true) != "on" || sw.Format(false) != "off" || MustLookup("1").Format(true) != "true" {
		t.Errorf("Format: %q %q %q", sw.Format(true), sw.Format(false), MustLookup("1").Format(true))
	}
	for s, want := range map[string]bool{"on": true, "ON": true, "off": false, "1": true, "0": false, "true": true, "no": false, "yes": true} {
		if v, err := sw.Parse(s); err != nil || v != want {
			t.Errorf("Parse(%q) = %v, %v", s, v, err)
		}
	}
	oc := MustLookup("1.009")
	if v, _ := oc.Parse("close"); v != true {
		t.Errorf("1.009 Parse(close) = %v", v)
	}
	if v, _ := oc.Parse("Open"); v != false {
		t.Errorf("1.009 Parse(Open) = %v", v)
	}
	if _, err := sw.Parse("maybe"); !errors.Is(err, knx.ErrInvalidValue) {
		t.Errorf("Parse(maybe): %v", err)
	}
	if _, err := MustLookup("1").Parse("close"); err == nil {
		t.Error("main type accepted a subtype label")
	}
}

func TestDPT2And3(t *testing.T) {
	if b := enc(t, "2.001", Control{Control: true, Value: false}); b[0] != 2 {
		t.Errorf("Control = % X", b)
	}
	c := MustLookup("2.001")
	for s, want := range map[string]Control{
		"1,0": {Control: true}, "0, 1": {Value: true}, "true": {Value: true}, "off": {},
		"control=true value=false": {Control: true}, "control=false value=true": {Value: true},
	} {
		if v, err := c.Parse(s); err != nil || v != want {
			t.Errorf("2.001 Parse(%q) = %v, %v", s, v, err)
		}
	}
	for _, s := range []string{"1,0,1", "x,1", "1,x", "control=x value=1"} {
		if _, err := c.Parse(s); !errors.Is(err, knx.ErrInvalidValue) {
			t.Errorf("2.001 Parse(%q): %v", s, err)
		}
	}
	if got := c.Format(Control{Control: true}); got != "control=true value=false" {
		t.Errorf("Format = %q", got)
	}

	if b := enc(t, "3.007", Step{Increase: true, StepCode: 3}); b[0] != 0x0B {
		t.Errorf("Step = % X", b)
	}
	_, err := MustLookup("3.007").Encode(Step{StepCode: 8})
	wantInvalid(t, "step code 8", err)
	s := MustLookup("3.008")
	for in, want := range map[string]Step{"+3": {Increase: true, StepCode: 3}, "-1": {StepCode: 1}, "stop": {}, "BREAK": {}, "+0": {Increase: true}} {
		if v, err := s.Parse(in); err != nil || v != want {
			t.Errorf("3.008 Parse(%q) = %v, %v", in, v, err)
		}
	}
	for _, in := range []string{"+8", "3", "+", "+x", "*1"} {
		if _, err := s.Parse(in); !errors.Is(err, knx.ErrInvalidValue) {
			t.Errorf("3.008 Parse(%q): %v", in, err)
		}
	}
	for v, want := range map[Step]string{{}: "stop", {Increase: true, StepCode: 0}: "stop", {Increase: true, StepCode: 2}: "+2", {StepCode: 7}: "-7"} {
		if got := s.Format(v); got != want {
			t.Errorf("Format(%+v) = %q", v, got)
		}
	}
}

func TestDPT4And16(t *testing.T) {
	cases := []struct {
		id, in, hex string
	}{
		{"4.001", "A", "41"}, {"4.001", "", "00"}, {"4.002", "é", "e9"}, {"4", "ÿ", "ff"},
		{"16.000", "", "0000000000000000000000000000"},
		{"16.000", "ab", "6162000000000000000000000000"},
		{"16.000", "abcdefghijklmn", "6162636465666768696a6b6c6d6e"},
		{"16.001", "Grüße", "4772fcdf65000000000000000000"},
		{"16", "KNX", "4b4e5800000000000000000000000000"[:28]},
	}
	for _, c := range cases {
		if b := enc(t, c.id, c.in); !bytes.Equal(b, hx(c.hex)) {
			t.Errorf("%s Encode(%q) = % X, want %s", c.id, c.in, b, c.hex)
		}
		if v := dec(t, c.id, hx(c.hex)); v != c.in {
			t.Errorf("%s Decode(%s) = %q, want %q", c.id, c.hex, v, c.in)
		}
	}
	for _, c := range []struct{ id, in string }{
		{"4.001", "é"}, {"4.001", "AB"}, {"4.002", "☃"}, {"4.001", "\x00"},
		{"16.000", "é"}, {"16.001", "☃"}, {"16.000", "abcdefghijklmno"}, {"16.000", "a\x00b"}, {"16.001", "Grüße Grüße Grü"},
	} {
		_, err := MustLookup(c.id).Encode(c.in)
		wantInvalid(t, c.id+" "+c.in, err)
	}
	// 14 ISO 8859-1 characters fit; their UTF-8 form is longer.
	if b := enc(t, "16.001", "éééééééééééééé"); !bytes.Equal(b, bytes.Repeat([]byte{0xe9}, 14)) {
		t.Errorf("14 é = % X", b)
	}
	// Format quotes, Parse unquotes.
	s := MustLookup("16.001")
	for _, in := range []string{"", "a b", `say "hi"`, "Grüße"} {
		f := s.Format(in)
		v, err := s.Parse(f)
		if err != nil || v != in {
			t.Errorf("Parse(Format(%q)) = Parse(%s) = %q, %v", in, f, v, err)
		}
	}
	if v, _ := s.Parse("plain text"); v != "plain text" {
		t.Errorf("Parse(plain text) = %q", v)
	}
	if v, _ := s.Parse(`"unterminated`); v != `"unterminated` {
		t.Errorf("Parse of a bad quote = %q", v)
	}
	if MustLookup("4.001").Format("A") != `"A"` {
		t.Errorf("4.001 Format = %s", MustLookup("4.001").Format("A"))
	}
}

func TestDPT5(t *testing.T) {
	cases := []struct {
		id   string
		in   float64
		want byte
	}{
		{"5.001", 0, 0x00}, {"5.001", 100, 0xFF}, {"5.001", 50, 0x80}, {"5.001", 1, 0x03},
		{"5.001", 0.2, 0x01}, {"5.001", 0.19, 0x00}, {"5.001", 99.6, 0xFE},
		{"5.003", 0, 0x00}, {"5.003", 360, 0xFF}, {"5.003", 180, 0x80}, {"5.003", 90, 0x40},
	}
	for _, c := range cases {
		if b := enc(t, c.id, c.in); b[0] != c.want {
			t.Errorf("%s Encode(%v) = %02X, want %02X", c.id, c.in, b[0], c.want)
		}
	}
	for _, c := range []struct {
		id string
		in float64
	}{{"5.001", -0.1}, {"5.001", 100.1}, {"5.003", 360.5}, {"5.003", -1}, {"5.001", math.NaN()}, {"5.001", math.Inf(1)}} {
		_, err := MustLookup(c.id).Encode(c.in)
		wantInvalid(t, c.id, err)
	}
	if v := dec(t, "5.001", []byte{0xFF}); v != 100.0 {
		t.Errorf("5.001 Decode(FF) = %v", v)
	}
	if v := dec(t, "5.003", []byte{0x80}); v != 128*360/255.0 {
		t.Errorf("5.003 Decode(80) = %v", v)
	}
	if got := MustLookup("5.001").Format(dec(t, "5.001", []byte{0x80})); got != "50.2 %" {
		t.Errorf("5.001 Format = %q", got)
	}
	if v, err := MustLookup("5.001").Parse("50.2 %"); err != nil || v != 50.2 {
		t.Errorf("5.001 Parse = %v, %v", v, err)
	}
	// Unscaled 5.x and the tariff range.
	if b := enc(t, "5.010", uint64(255)); b[0] != 0xFF {
		t.Errorf("5.010 255 = % X", b)
	}
	for _, v := range []any{256, -1, uint64(256)} {
		_, err := MustLookup("5.010").Encode(v)
		wantInvalid(t, "5.010", err)
	}
	if b := enc(t, "5.006", 254); b[0] != 0xFE {
		t.Errorf("5.006 254 = % X", b)
	}
	for _, v := range []any{255, uint64(255)} {
		_, err := MustLookup("5.006").Encode(v)
		wantInvalid(t, "5.006 255", err)
	}
}

func TestIntegerBoundaries(t *testing.T) {
	cases := []struct {
		id         string
		lo, hi     int64
		loHex, hiH string
	}{
		{"5.010", 0, 255, "00", "ff"},
		{"6.001", -128, 127, "80", "7f"},
		{"6.010", -128, 127, "80", "7f"},
		{"7.001", 0, 65535, "0000", "ffff"},
		{"8.001", -32768, 32767, "8000", "7fff"},
		{"12.001", 0, 4294967295, "00000000", "ffffffff"},
		{"13.001", -2147483648, 2147483647, "80000000", "7fffffff"},
		{"29.010", math.MinInt64, math.MaxInt64, "8000000000000000", "7fffffffffffffff"},
	}
	for _, c := range cases {
		ty := MustLookup(c.id)
		for _, x := range []struct {
			v int64
			h string
		}{{c.lo, c.loHex}, {c.hi, c.hiH}} {
			b, err := ty.Encode(x.v)
			if err != nil || !bytes.Equal(b, hx(x.h)) {
				t.Errorf("%s Encode(%d) = % X, %v; want %s", c.id, x.v, b, err, x.h)
			}
			v := dec(t, c.id, hx(x.h))
			if fmtInt(v) != x.v {
				t.Errorf("%s Decode(%s) = %v", c.id, x.h, v)
			}
		}
		if c.id != "29.010" {
			for _, v := range []int64{c.lo - 1, c.hi + 1} {
				_, err := ty.Encode(v)
				wantInvalid(t, c.id+" outside", err)
			}
		}
	}
	// A uint64 beyond int64 is not a DPT 29 value.
	_, err := MustLookup("29.010").Encode(uint64(math.MaxInt64) + 1)
	wantInvalid(t, "29.010 2^63", err)
	if strconv.IntSize == 64 {
		// uint has 64 bits here: one above the int64 range.
		big := ^uint(0)
		_, err = MustLookup("29.010").Encode(big)
		wantInvalid(t, "29.010 uint max", err)
	}
}

func fmtInt(v any) int64 {
	switch x := v.(type) {
	case uint64:
		return int64(x)
	case int64:
		return x
	}
	return -42
}

func TestScaledIntegers(t *testing.T) {
	cases := []struct {
		id  string
		in  float64
		hex string
	}{
		{"7.003", 655350, "ffff"}, {"7.003", 15, "0002"}, {"7.004", 100, "0001"},
		{"8.010", -327.68, "8000"}, {"8.010", 327.67, "7fff"}, {"8.010", 1.5, "0096"},
		{"13.002", 1, "00002710"}, {"13.002", -0.0001, "ffffffff"},
	}
	for _, c := range cases {
		if b := enc(t, c.id, c.in); !bytes.Equal(b, hx(c.hex)) {
			t.Errorf("%s Encode(%v) = % X, want %s", c.id, c.in, b, c.hex)
		}
	}
	for _, c := range []struct {
		id string
		in float64
	}{{"7.003", 655360}, {"7.003", -10}, {"8.010", 327.68}, {"8.010", -327.69}, {"7.004", math.Inf(-1)}} {
		_, err := MustLookup(c.id).Encode(c.in)
		wantInvalid(t, c.id, err)
	}
	if v := dec(t, "8.010", hx("8000")); v != -327.68 {
		t.Errorf("8.010 Decode(8000) = %v", v)
	}
	if v, err := MustLookup("7.003").Parse("150 ms"); err != nil || v != 150.0 {
		t.Errorf("7.003 Parse = %v, %v", v, err)
	}
	if _, err := MustLookup("7.003").Parse("x ms"); !errors.Is(err, knx.ErrInvalidValue) {
		t.Errorf("7.003 Parse(x): %v", err)
	}
}

func TestInputConversions(t *testing.T) {
	ty := MustLookup("9.001")
	for _, v := range []any{21, int8(21), int16(21), int32(21), int64(21), uint(21), uint8(21), uint16(21), uint32(21), uint64(21), float32(21), 21.0} {
		if b, err := ty.Encode(v); err != nil || !bytes.Equal(b, hx("0c1a")) {
			t.Errorf("9.001 Encode(%T 21) = % X, %v", v, b, err)
		}
	}
	u := MustLookup("7.001")
	for _, v := range []any{1, int8(1), int16(1), int32(1), int64(1), uint(1), uint8(1), uint16(1), uint32(1), uint64(1), 1.0, float32(1)} {
		if b, err := u.Encode(v); err != nil || !bytes.Equal(b, hx("0001")) {
			t.Errorf("7.001 Encode(%T 1) = % X, %v", v, b, err)
		}
	}
	for _, v := range []any{1.5, float32(1.5), math.NaN(), 1e19, float32(1e30), float32(-1e30), "1", nil} {
		_, err := MustLookup("13.001").Encode(v)
		wantInvalid(t, "13.001 non-integer", err)
	}
	// A huge float32 is not taken as an int64 (whose conversion would be
	// implementation-defined).
	_, err := MustLookup("29.010").Encode(float32(1e30))
	wantInvalid(t, "29.010 float32 1e30", err)
}

func TestDPT9(t *testing.T) {
	cases := []struct {
		in  float64
		raw uint16
	}{
		{0, 0x0000}, {21.5, 0x0C33}, {-30, 0x8A24}, {0.01, 0x0001}, {-0.01, 0x87FF}, {0.02, 0x0002},
		{20.47, 0x07FF}, {20.48, 0x0C00}, {-20.48, 0x8000}, {100, 0x1CE2}, {-273, 0xA156},
		{670433.28, 0x7FFE}, {-671088.64, 0xF800}, {655.36, 0x3400},
		{0.005, 0x0001}, {-0.005, 0x87FF}, {0.004, 0x0000}, // rounding half away from zero
		{0.125, 0x000D}, {0.375, 0x0026},
		{20.475, 0x0C00}, // 2047.5 rounds to 2048, which needs exponent 1
	}
	for _, c := range cases {
		raw, err := EncodeFloat16(c.in)
		if err != nil || raw != c.raw {
			t.Errorf("EncodeFloat16(%v) = %04X, %v; want %04X", c.in, raw, err, c.raw)
		}
	}
	for _, f := range []float64{670433.29, 670760, -671088.65, 1e9, math.NaN(), math.Inf(1), math.Inf(-1)} {
		_, err := EncodeFloat16(f)
		wantInvalid(t, "EncodeFloat16", err)
	}
	for raw, want := range map[uint16]float64{0x0000: 0, 0x0C33: 21.5, 0x8A24: -30, 0x0001: 0.01, 0x87FF: -0.01, 0x7FFE: 670433.28, 0xF800: -671088.64, 0x0801: 0.02} {
		if f, err := DecodeFloat16(raw); err != nil || f != want {
			t.Errorf("DecodeFloat16(%04X) = %v, %v; want %v", raw, f, err, want)
		}
	}
	if _, err := DecodeFloat16(0x7FFF); !errors.Is(err, ErrFloat16Invalid) || !errors.Is(err, knx.ErrInvalidValue) {
		t.Errorf("DecodeFloat16(7FFF): %v", err)
	}
	// Subtype ranges are checked on encode.
	_, err := MustLookup("9.001").Encode(-273.01)
	wantInvalid(t, "9.001 below absolute zero", err)
	_, err = MustLookup("9.004").Encode(-1)
	wantInvalid(t, "9.004 negative lux", err)
	if b := enc(t, "9.001", -273); !bytes.Equal(b, hx("a156")) {
		t.Errorf("9.001 -273 = % X", b)
	}
	if got := MustLookup("9.001").Format(21.5); got != "21.5 °C" {
		t.Errorf("Format = %q", got)
	}
	for _, s := range []string{"21.5", "21.5 °C", "21.5°C", " 21.5 "} {
		if v, err := MustLookup("9.001").Parse(s); err != nil || v != 21.5 {
			t.Errorf("Parse(%q) = %v, %v", s, v, err)
		}
	}
}

// TestDPT9Exhaustive decodes every 2-octet float, re-encodes it and checks
// the encoding is canonical: the smallest exponent that represents the
// value exactly.
func TestDPT9Exhaustive(t *testing.T) {
	for r := 0; r <= 0xFFFF; r++ {
		raw := uint16(r)
		f, err := DecodeFloat16(raw)
		if raw == 0x7FFF {
			if err == nil {
				t.Fatal("0x7FFF decoded")
			}
			continue
		}
		if err != nil {
			t.Fatalf("%04X: %v", raw, err)
		}
		raw2, err := EncodeFloat16(f)
		if err != nil {
			t.Fatalf("%04X → %v: %v", raw, f, err)
		}
		f2, _ := DecodeFloat16(raw2)
		if f2 != f {
			t.Fatalf("%04X → %v → %04X → %v", raw, f, raw2, f2)
		}
		m := int(raw & 0x07FF)
		if raw&0x8000 != 0 {
			m -= 2048
		}
		e := raw >> 11 & 0x0F
		canonical := e == 0 || m >= 1024 || m < -1024
		if (raw2 == raw) != canonical {
			t.Fatalf("%04X (m %d e %d) re-encodes as %04X", raw, m, e, raw2)
		}
	}
}

func TestDPT14(t *testing.T) {
	cases := []struct {
		in  float64
		hex string
	}{
		{0, "00000000"}, {1.5, "3fc00000"}, {-0.1, "bdcccccd"}, {230, "43660000"}, {-256, "c3800000"},
		{math.MaxFloat32, "7f7fffff"}, {3.4028235e38, "7f7fffff"}, {1e-45, "00000001"},
	}
	for _, c := range cases {
		if b := enc(t, "14.056", c.in); !bytes.Equal(b, hx(c.hex)) {
			t.Errorf("Encode(%v) = % X, want %s", c.in, b, c.hex)
		}
	}
	// Decoding gives the shortest decimal of the float32.
	for h, want := range map[string]float64{"bdcccccd": -0.1, "7f7fffff": 3.4028235e38, "00000001": 1e-45, "3fc00000": 1.5} {
		if v := dec(t, "14.056", hx(h)); v != want {
			t.Errorf("Decode(%s) = %v, want %v", h, v, want)
		}
	}
	for _, f := range []float64{3.5e38, -1e39, math.NaN(), math.Inf(1)} {
		_, err := MustLookup("14.056").Encode(f)
		wantInvalid(t, "14.056 out of range", err)
	}
}

func TestDPT10And11(t *testing.T) {
	ty := MustLookup("10.001")
	if b := enc(t, "10.001", TimeOfDay{Weekday: 1, Hour: 12, Minute: 30, Second: 5}); !bytes.Equal(b, hx("2c1e05")) {
		t.Errorf("time = % X", b)
	}
	for _, v := range []TimeOfDay{{Weekday: 8}, {Hour: 24}, {Minute: 60}, {Second: 60}} {
		_, err := ty.Encode(v)
		wantInvalid(t, "time", err)
	}
	for in, want := range map[string]TimeOfDay{
		"12:30":        {Hour: 12, Minute: 30},
		"12:30:05":     {Hour: 12, Minute: 30, Second: 5},
		"Sun 23:59:59": {Weekday: 7, Hour: 23, Minute: 59, Second: 59},
		"mon 00:00":    {Weekday: 1},
	} {
		if v, err := ty.Parse(in); err != nil || v != want {
			t.Errorf("Parse(%q) = %v, %v", in, v, err)
		}
	}
	for _, in := range []string{"Foo 12:00", "24:00", "12", "12:60", "12:00:60", "12:00:00:00", "a:b"} {
		if _, err := ty.Parse(in); !errors.Is(err, knx.ErrInvalidValue) {
			t.Errorf("Parse(%q): %v", in, err)
		}
	}
	for v, want := range map[TimeOfDay]string{{Weekday: 7, Hour: 23, Minute: 59, Second: 59}: "Sun 23:59:59", {Hour: 1, Minute: 2, Second: 3}: "01:02:03"} {
		if ty.Format(v) != want || v.String() != want {
			t.Errorf("Format(%+v) = %q", v, ty.Format(v))
		}
	}

	d := MustLookup("11.001")
	for _, c := range []struct {
		v   Date
		hex string
	}{{Date{2026, 10, 29}, "1d0a1a"}, {Date{1990, 1, 1}, "01015a"}, {Date{2089, 12, 31}, "1f0c59"}, {Date{2000, 1, 1}, "010100"}, {Date{1999, 12, 31}, "1f0c63"}} {
		if b := enc(t, "11.001", c.v); !bytes.Equal(b, hx(c.hex)) {
			t.Errorf("Encode(%v) = % X, want %s", c.v, b, c.hex)
		}
		if v := dec(t, "11.001", hx(c.hex)); v != c.v {
			t.Errorf("Decode(%s) = %v", c.hex, v)
		}
	}
	for _, v := range []Date{{1989, 12, 31}, {2090, 1, 1}, {2026, 0, 1}, {2026, 13, 1}, {2026, 1, 0}, {2026, 1, 32}} {
		_, err := d.Encode(v)
		wantInvalid(t, "date "+v.String(), err)
	}
	if v, err := d.Parse("2026-10-29"); err != nil || v != (Date{2026, 10, 29}) {
		t.Errorf("Parse = %v, %v", v, err)
	}
	for _, in := range []string{"2026-10", "2026-xx-01", "29.10.2026"} {
		if _, err := d.Parse(in); !errors.Is(err, knx.ErrInvalidValue) {
			t.Errorf("Parse(%q): %v", in, err)
		}
	}
	if d.Format(Date{2026, 1, 2}) != "2026-01-02" {
		t.Errorf("Format = %q", d.Format(Date{2026, 1, 2}))
	}
}

func TestDPT19(t *testing.T) {
	ty := MustLookup("19.001")
	full := DateTime{Year: 2026, Month: 10, Day: 29, Weekday: 4, Hour: 12, Minute: 30, Second: 5, WorkingDay: true, SummerTime: true, ExternalSync: true}
	if b := enc(t, "19.001", full); !bytes.Equal(b, hx("7e0a1d8c1e054180")) {
		t.Errorf("Encode = % X", b)
	}
	flags := DateTime{Year: 1900, Month: 1, Day: 1, Fault: true, WorkingDay: true, NoWorkingDay: true, NoYear: true, NoDate: true,
		NoWeekday: true, NoTime: true, SummerTime: true, ExternalSync: true, ReliableSource: true}
	if b := enc(t, "19.001", flags); !bytes.Equal(b, hx("0001010000 00 ffc0")) {
		t.Errorf("all flags = % X", b)
	}
	// Fields flagged invalid need only fit their bits.
	for _, v := range []DateTime{
		{Year: 2000, NoDate: true},
		{Year: 2000, Month: 15, Day: 31, NoDate: true, Hour: 1},
		{Year: 2000, Month: 1, Day: 1, NoTime: true, Hour: 31, Minute: 63, Second: 63},
		{Year: 2000, Month: 1, Day: 1, Hour: 24},
	} {
		b, err := ty.Encode(v)
		if err != nil {
			t.Errorf("Encode(%+v): %v", v, err)
			continue
		}
		if got, err := ty.Decode(b); err != nil || got != v {
			t.Errorf("round trip %+v → % X → %+v, %v", v, b, got, err)
		}
	}
	for _, v := range []DateTime{
		{Year: 1899, Month: 1, Day: 1}, {Year: 2156, Month: 1, Day: 1}, {Year: 2000, Month: 0, Day: 1}, {Year: 2000, Month: 13, Day: 1},
		{Year: 2000, Month: 1, Day: 0}, {Year: 2000, Month: 1, Day: 32}, {Year: 2000, Month: 1, Day: 1, Weekday: 8},
		{Year: 2000, Month: 1, Day: 1, Hour: 25}, {Year: 2000, Month: 1, Day: 1, Minute: 60}, {Year: 2000, Month: 1, Day: 1, Second: 60},
		{Year: 2000, Month: 1, Day: 1, Hour: 24, Second: 1}, {Year: 2000, Month: 1, Day: 1, Hour: 24, Minute: 1},
		{Year: 2000, Month: 16, NoDate: true}, {Year: 2000, Day: 32, NoDate: true},
		{Year: 2000, Month: 1, Day: 1, NoTime: true, Hour: 32}, {Year: 2000, Month: 1, Day: 1, NoTime: true, Minute: 64},
		{Year: 2000, Month: 1, Day: 1, NoTime: true, Second: 64},
	} {
		_, err := ty.Encode(v)
		wantInvalid(t, "19.001 "+v.String(), err)
	}
	if v, err := ty.Parse("2026-10-29 12:30:05"); err != nil || v != (DateTime{Year: 2026, Month: 10, Day: 29, Hour: 12, Minute: 30, Second: 5, NoWeekday: true, NoWorkingDay: true}) {
		t.Errorf("Parse = %+v, %v", v, err)
	}
	if v, err := ty.Parse("2026-10-29T12:30"); err != nil || v.(DateTime).Minute != 30 {
		t.Errorf("Parse ISO = %+v, %v", v, err)
	}
	for _, in := range []string{"2026-10-29", "2026-10-29 25", "x 12:00", "2026-10-29 12:61"} {
		if _, err := ty.Parse(in); !errors.Is(err, knx.ErrInvalidValue) {
			t.Errorf("Parse(%q): %v", in, err)
		}
	}
	if ty.Format(full) != "2026-10-29 12:30:05" {
		t.Errorf("Format = %q", ty.Format(full))
	}
}

func TestScenes(t *testing.T) {
	if b := enc(t, "17.001", 63); b[0] != 63 {
		t.Errorf("scene 63 = % X", b)
	}
	for _, v := range []any{64, -1, 1.5} {
		_, err := MustLookup("17.001").Encode(v)
		wantInvalid(t, "scene", err)
	}
	if v, err := MustLookup("17.001").Parse("12"); err != nil || v != uint8(12) {
		t.Errorf("Parse = %v, %v", v, err)
	}
	if _, err := MustLookup("17.001").Parse("x"); !errors.Is(err, knx.ErrInvalidValue) {
		t.Errorf("Parse(x): %v", err)
	}

	sc := MustLookup("18.001")
	if b := enc(t, "18.001", SceneControl{Learn: true, Scene: 5}); b[0] != 0x85 {
		t.Errorf("learn 5 = % X", b)
	}
	_, err := sc.Encode(SceneControl{Scene: 64})
	wantInvalid(t, "scene control 64", err)
	for in, want := range map[string]SceneControl{"learn 5": {Learn: true, Scene: 5}, "Activate 7": {Scene: 7}, "9": {Scene: 9}} {
		if v, err := sc.Parse(in); err != nil || v != want {
			t.Errorf("Parse(%q) = %v, %v", in, v, err)
		}
	}
	for _, in := range []string{"learn 64", "learn", "x"} {
		if _, err := sc.Parse(in); !errors.Is(err, knx.ErrInvalidValue) {
			t.Errorf("Parse(%q): %v", in, err)
		}
	}
	if sc.Format(SceneControl{Learn: true, Scene: 5}) != "learn 5" || sc.Format(SceneControl{Scene: 5}) != "activate 5" {
		t.Error("scene control Format")
	}
	// 26.001 keeps the octet as a bit set.
	if v := dec(t, "26.001", []byte{0x45}); v != uint64(0x45) {
		t.Errorf("26.001 = %v", v)
	}
}

func TestDPT20(t *testing.T) {
	ty := MustLookup("20.102")
	for _, v := range []any{Enum{Value: 3}, "economy", "ECONOMY", 3, uint8(3)} {
		if b, err := ty.Encode(v); err != nil || b[0] != 3 {
			t.Errorf("Encode(%#v) = % X, %v", v, b, err)
		}
	}
	for _, v := range []any{5, "foo", -1, 256, Enum{Value: 9}, 1.5} {
		_, err := ty.Encode(v)
		wantInvalid(t, "20.102", err)
	}
	if v := dec(t, "20.102", []byte{1}); v != (Enum{Value: 1, Name: "comfort"}) {
		t.Errorf("Decode(1) = %v", v)
	}
	if v := dec(t, "20", []byte{0xFF}); v != (Enum{Value: 255}) || v.(Enum).String() != "255" {
		t.Errorf("main 20 Decode(FF) = %v", v)
	}
	if b := enc(t, "20", 200); b[0] != 200 {
		t.Errorf("main 20 Encode(200) = % X", b)
	}
	for in, want := range map[string]Enum{"1": {1, "comfort"}, "economy": {3, "economy"}, "Building Protection": {4, "building protection"}} {
		if v, err := ty.Parse(in); err != nil || v != want {
			t.Errorf("Parse(%q) = %v, %v", in, v, err)
		}
	}
	if _, err := ty.Parse("x"); !errors.Is(err, knx.ErrInvalidValue) {
		t.Errorf("Parse(x): %v", err)
	}
	if ty.Format(Enum{3, "economy"}) != "economy" {
		t.Errorf("Format = %q", ty.Format(Enum{3, "economy"}))
	}
	// Every name of every enumeration parses back to its value.
	for _, e := range All() {
		for k, n := range e.Enum {
			if v, err := e.Parse(n); err != nil || v.(Enum).Value != k {
				t.Errorf("%s Parse(%q) = %v, %v", e, n, v, err)
			}
		}
	}
}

func TestBits(t *testing.T) {
	if b := enc(t, "21.001", 0xFF); b[0] != 0xFF {
		t.Errorf("21.001 = % X", b)
	}
	if b := enc(t, "22", 0xABCD); !bytes.Equal(b, hx("abcd")) {
		t.Errorf("22 = % X", b)
	}
	for _, v := range []any{256, -1, "x"} {
		_, err := MustLookup("21.001").Encode(v)
		wantInvalid(t, "21.001", err)
	}
	ty := MustLookup("21.001")
	if ty.Format(uint64(5)) != "0b00000101" {
		t.Errorf("Format = %q", ty.Format(uint64(5)))
	}
	for in, want := range map[string]uint64{"0b00000101": 5, "0x05": 5, "5": 5, "255": 255} {
		if v, err := ty.Parse(in); err != nil || v != want {
			t.Errorf("Parse(%q) = %v, %v", in, v, err)
		}
	}
	for _, in := range []string{"256", "x", "-1"} {
		if _, err := ty.Parse(in); !errors.Is(err, knx.ErrInvalidValue) {
			t.Errorf("Parse(%q): %v", in, err)
		}
	}
}

func TestColours(t *testing.T) {
	rgb := MustLookup("232.600")
	if b := enc(t, "232.600", RGB{0xFF, 0x80, 0x00}); !bytes.Equal(b, hx("ff8000")) {
		t.Errorf("RGB = % X", b)
	}
	for _, in := range []string{"#FF8000", "ff8000"} {
		if v, err := rgb.Parse(in); err != nil || v != (RGB{0xFF, 0x80, 0x00}) {
			t.Errorf("Parse(%q) = %v, %v", in, v, err)
		}
	}
	for _, in := range []string{"#FF80", "#GG0000", "#FF800000"} {
		if _, err := rgb.Parse(in); !errors.Is(err, knx.ErrInvalidValue) {
			t.Errorf("Parse(%q): %v", in, err)
		}
	}
	if rgb.Format(RGB{1, 2, 3}) != "#010203" {
		t.Errorf("Format = %q", rgb.Format(RGB{1, 2, 3}))
	}

	rgbw := MustLookup("251.600")
	if b := enc(t, "251.600", RGBW{R: 1, G: 2, B: 3, W: 4, ValidR: true, ValidW: true}); !bytes.Equal(b, hx("010203040009")) {
		t.Errorf("RGBW = % X", b)
	}
	if v, err := rgbw.Parse("#01020304"); err != nil || v != (RGBW{1, 2, 3, 4, true, true, true, true}) {
		t.Errorf("Parse = %v, %v", v, err)
	}
	if _, err := rgbw.Parse("#010203"); !errors.Is(err, knx.ErrInvalidValue) {
		t.Errorf("Parse(#010203): %v", err)
	}
	if rgbw.Format(RGBW{R: 1, G: 2, B: 3, W: 4}) != "#01020304" {
		t.Error("RGBW Format")
	}

	xyy := MustLookup("242.600")
	c := XYY{X: 0.5, Y: 0.25, Brightness: 50, ColorValid: true, BrightnessValid: true}
	if b := enc(t, "242.600", c); !bytes.Equal(b, hx("800040008003")) {
		t.Errorf("xyY = % X", b)
	}
	for _, v := range []XYY{{X: 1.01}, {Y: -0.1}, {X: -0.01}, {Y: 1.5}, {Brightness: 100.5}, {Brightness: -1}} {
		_, err := xyy.Encode(v)
		wantInvalid(t, "xyY", err)
	}
	if v, err := xyy.Parse("0.5, 0.25, 50"); err != nil || v != c {
		t.Errorf("Parse = %v, %v", v, err)
	}
	f := xyy.Format(c)
	if f != "x=0.5000 y=0.2500 brightness=50.0 %" {
		t.Errorf("Format = %q", f)
	}
	if v, err := xyy.Parse(f); err != nil || v != c {
		t.Errorf("Parse(Format) = %v, %v", v, err)
	}
	for _, in := range []string{"0.5,0.25", "a,b,c", "x=a y=0 brightness=0 %"} {
		if _, err := xyy.Parse(in); !errors.Is(err, knx.ErrInvalidValue) {
			t.Errorf("Parse(%q): %v", in, err)
		}
	}
}

// TestFormatParse checks for every type and sample value that Parse
// accepts what Format prints and that the text is then stable.
func TestFormatParse(t *testing.T) {
	for _, ty := range append(All(), Mains()...) {
		for _, v := range samples(ty) {
			// Format prints decoded values; normalise floats first.
			b, err := ty.Encode(v)
			if err != nil {
				t.Fatalf("%s: %v", ty, err)
			}
			dv, _ := ty.Decode(b)
			if d, ok := dv.(DateTime); ok && (d.NoDate || d.NoTime) {
				// Format prints no flags, so the invalid fields of such a
				// value are not text that Parse reads.
				continue
			}
			s := ty.Format(dv)
			pv, err := ty.Parse(s)
			if err != nil {
				t.Errorf("%s: Parse(Format(%#v) = %q): %v", ty, dv, s, err)
				continue
			}
			if s2 := ty.Format(pv); s2 != s {
				t.Errorf("%s: %q → %#v → %q", ty, s, pv, s2)
			}
			if _, err := ty.Encode(pv); err != nil {
				t.Errorf("%s: parsed %#v does not encode: %v", ty, pv, err)
			}
		}
	}
	// A value of the wrong type is printed with fmt.
	if got := MustLookup("1.001").Format(7); got != "7" {
		t.Errorf("Format(7) = %q", got)
	}
	if got := MustLookup("7.001").Format(uint64(5)); got != "5 pulses" {
		t.Errorf("7.001 Format = %q", got)
	}
	if got := MustLookup("5.001").Format("x"); got != "x %" {
		t.Errorf("5.001 Format(x) = %q", got)
	}
}

func TestParseErrorsNumeric(t *testing.T) {
	for _, c := range []struct{ id, in string }{
		{"9.001", "abc"}, {"9.001", "21,5"}, {"5.010", "-1"}, {"6.001", "x"}, {"14.056", ""}, {"5.001", "half"},
	} {
		_, err := MustLookup(c.id).Parse(c.in)
		wantInvalid(t, c.id+" "+c.in, err)
		if err != nil && !strings.HasPrefix(err.Error(), "dpt "+c.id+": ") {
			t.Errorf("error %q lacks the type prefix", err)
		}
	}
	if v, err := MustLookup("6.001").Parse("-0x10"); err != nil || v != int64(-16) {
		t.Errorf("6.001 Parse(-0x10) = %v, %v", v, err)
	}
}

func TestParseID(t *testing.T) {
	ok := []struct {
		in     string
		id     ID
		hasSub bool
	}{
		{"9.001", ID{9, 1}, true}, {"9.1", ID{9, 1}, true}, {"DPT9.001", ID{9, 1}, true}, {"dpt9.1", ID{9, 1}, true},
		{"DPST-9-1", ID{9, 1}, true}, {"dpst-9-1", ID{9, 1}, true}, {"DPT-9-1", ID{9, 1}, true}, {"DPT-9", ID{9, 0}, false},
		{"9", ID{9, 0}, false}, {" 9.001 ", ID{9, 1}, true}, {"12.1200", ID{12, 1200}, true}, {"9.000", ID{9, 0}, true},
		{"DPT9", ID{9, 0}, false}, {"232.600", ID{232, 600}, true},
	}
	for _, c := range ok {
		id, hasSub, err := ParseID(c.in)
		if err != nil || id != c.id || hasSub != c.hasSub {
			t.Errorf("ParseID(%q) = %v %v %v", c.in, id, hasSub, err)
		}
	}
	for _, in := range []string{"", "DPT", "DPT-", "9.", ".1", "9.1.1", "x", "DPT-9-1-1", "-9", "9.-1", "+9", "70000", "9.70000", "DPST-9-x"} {
		if _, _, err := ParseID(in); !errors.Is(err, knx.ErrInvalidOption) {
			t.Errorf("ParseID(%q): %v", in, err)
		}
	}
	for id, want := range map[ID]string{{9, 1}: "9.001", {12, 1200}: "12.1200", {9, 0}: "9.000", {232, 600}: "232.600"} {
		if id.String() != want {
			t.Errorf("%v.String() = %q", id, id.String())
		}
	}
}

func TestLookup(t *testing.T) {
	temp := MustLookup("9.001")
	if temp.Name != "DPT_Value_Temp" || temp.Unit != "°C" || temp.String() != "9.001 DPT_Value_Temp" {
		t.Errorf("9.001 = %+v", temp)
	}
	for _, s := range []string{"9.1", "DPT9.001", "DPST-9-1", "DPT-9-1"} {
		if got, err := Lookup(s); err != nil || got != temp {
			t.Errorf("Lookup(%q) = %v, %v", s, got, err)
		}
	}
	for _, s := range []string{"9", "DPT-9", "DPT9"} {
		if got, err := Lookup(s); err != nil || got.ID != (ID{9, 0}) || got.Name != "DPT_9" {
			t.Errorf("Lookup(%q) = %v, %v", s, got, err)
		}
	}
	for _, s := range []string{"9.999", "9.000", "99", "99.001", "15.000"} {
		if _, err := Lookup(s); !errors.Is(err, knx.ErrUnsupported) {
			t.Errorf("Lookup(%q): %v, want ErrUnsupported", s, err)
		}
	}
	if _, err := Lookup("nine"); !errors.Is(err, knx.ErrInvalidOption) {
		t.Errorf("Lookup(nine): %v", err)
	}
	if _, ok := Get(ID{9, 999}); ok {
		t.Error("Get(9.999) found")
	}
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustLookup(9.999) did not panic")
		}
	}()
	MustLookup("9.999")
}

func TestRegisterDuplicatePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("duplicate register did not panic")
		}
	}()
	register(&Type{ID: ID{9, 1}})
}

func TestKindAndValueStrings(t *testing.T) {
	for k, want := range map[Kind]string{KindBool: "bool", KindSceneControl: "scene-control", KindXYY: "xyY", Kind(99): "Kind(99)"} {
		if k.String() != want {
			t.Errorf("%d.String() = %q", int(k), k.String())
		}
	}
	for i := range kindNames {
		if _, ok := goType[Kind(i)]; !ok {
			t.Errorf("kind %s has no Go type in the test table", Kind(i))
		}
	}
	cases := []struct{ got, want string }{
		{TimeOfDay{Weekday: 8, Hour: 1}.String(), "01:00:00"},
		{Date{2026, 10, 29}.String(), "2026-10-29"},
		{DateTime{Year: 2026, Month: 1, Day: 2, Hour: 3, Minute: 4, Second: 5}.String(), "2026-01-02 03:04:05"},
		{Enum{Value: 3, Name: "economy"}.String(), "economy"},
		{RGB{255, 0, 16}.String(), "#FF0010"},
		{RGBW{1, 2, 3, 4, false, false, false, false}.String(), "#01020304"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}
