// SPDX-License-Identifier: MIT

package dpt

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ---- conversions of accepted inputs ----

func toBool(v any) (bool, error) {
	switch x := v.(type) {
	case bool:
		return x, nil
	case int:
		if x == 0 || x == 1 {
			return x == 1, nil
		}
	case uint8:
		if x <= 1 {
			return x == 1, nil
		}
	}
	return false, errValue("%v (%T) is not a boolean", v, v)
}

func toFloat(v any) (float64, error) {
	switch x := v.(type) {
	case float64:
		return x, nil
	case float32:
		return float64(x), nil
	case int:
		return float64(x), nil
	case int8:
		return float64(x), nil
	case int16:
		return float64(x), nil
	case int32:
		return float64(x), nil
	case int64:
		return float64(x), nil
	case uint:
		return float64(x), nil
	case uint8:
		return float64(x), nil
	case uint16:
		return float64(x), nil
	case uint32:
		return float64(x), nil
	case uint64:
		return float64(x), nil
	}
	return 0, errValue("%v (%T) is not a number", v, v)
}

func toInt(v any) (int64, error) {
	switch x := v.(type) {
	case int:
		return int64(x), nil
	case int8:
		return int64(x), nil
	case int16:
		return int64(x), nil
	case int32:
		return int64(x), nil
	case int64:
		return x, nil
	case uint:
		if uint64(x) <= math.MaxInt64 {
			return int64(x), nil
		}
	case uint8:
		return int64(x), nil
	case uint16:
		return int64(x), nil
	case uint32:
		return int64(x), nil
	case uint64:
		if x <= math.MaxInt64 {
			return int64(x), nil
		}
	case float64:
		if x == math.Trunc(x) && x >= -9.2e18 && x <= 9.2e18 {
			return int64(x), nil
		}
	case float32:
		if f := float64(x); f == math.Trunc(f) && f >= -9.2e18 && f <= 9.2e18 {
			return int64(f), nil
		}
	}
	return 0, errValue("%v (%T) is not an integer", v, v)
}

func checkRange(t *Type, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return errValue("%v is not a finite number", f)
	}
	if t.HasRange && (f < t.Min || f > t.Max) {
		return errValue("%v out of range %v..%v", f, t.Min, t.Max)
	}
	return nil
}

func parseBoolText(t *Type, s string) (bool, error) {
	switch strings.ToLower(s) {
	case "1", "true", "on", "yes":
		return true, nil
	case "0", "false", "off", "no":
		return false, nil
	}
	if len(t.Labels) == 2 {
		if strings.EqualFold(s, t.Labels[1]) {
			return true, nil
		}
		if strings.EqualFold(s, t.Labels[0]) {
			return false, nil
		}
	}
	return false, errValue("%q is not a boolean (true/false, on/off, 1/0)", s)
}

// ---- DPT 1: boolean ----

var boolCodec = codec{
	encode: func(t *Type, v any) ([]byte, error) {
		b, err := toBool(v)
		if err != nil {
			return nil, err
		}
		if b {
			return []byte{1}, nil
		}
		return []byte{0}, nil
	},
	decode: func(t *Type, b []byte) (any, error) { return b[0] == 1, nil },
	parse:  func(t *Type, s string) (any, error) { return parseBoolText(t, s) },
	format: func(t *Type, v any) (string, bool) {
		b, ok := v.(bool)
		if !ok {
			return "", false
		}
		if len(t.Labels) == 2 {
			if b {
				return t.Labels[1], true
			}
			return t.Labels[0], true
		}
		return strconv.FormatBool(b), true
	},
}

// ---- DPT 2: boolean with control ----

var controlCodec = codec{
	encode: func(t *Type, v any) ([]byte, error) {
		c, ok := v.(Control)
		if !ok {
			return nil, errValue("%v (%T) is not a dpt.Control", v, v)
		}
		var b byte
		if c.Control {
			b |= 2
		}
		if c.Value {
			b |= 1
		}
		return []byte{b}, nil
	},
	decode: func(t *Type, b []byte) (any, error) { return Control{Control: b[0]&2 != 0, Value: b[0]&1 != 0}, nil },
	parse: func(t *Type, s string) (any, error) {
		// "control,value": "1,0", "true,on"; a single value means no control.
		// Format's "control=true value=false" is accepted too.
		if c, v, ok := strings.Cut(s, " "); ok && strings.HasPrefix(c, "control=") && strings.HasPrefix(v, "value=") {
			s = c[len("control="):] + "," + v[len("value="):]
		}
		parts := strings.Split(s, ",")
		if len(parts) == 1 {
			v, err := parseBoolText(t, parts[0])
			return Control{Value: v}, err
		}
		if len(parts) != 2 {
			return nil, errValue("%q: want control,value (1,0)", s)
		}
		c, err := parseBoolText(t, strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, err
		}
		v, err := parseBoolText(t, strings.TrimSpace(parts[1]))
		return Control{Control: c, Value: v}, err
	},
	format: func(t *Type, v any) (string, bool) {
		c, ok := v.(Control)
		if !ok {
			return "", false
		}
		return fmt.Sprintf("control=%t value=%t", c.Control, c.Value), true
	},
}

// ---- DPT 3: 3-bit controlled ----

var stepCodec = codec{
	encode: func(t *Type, v any) ([]byte, error) {
		s, ok := v.(Step)
		if !ok {
			return nil, errValue("%v (%T) is not a dpt.Step", v, v)
		}
		if s.StepCode > 7 {
			return nil, errValue("step code %d out of range 0..7", s.StepCode)
		}
		b := s.StepCode
		if s.Increase {
			b |= 8
		}
		return []byte{b}, nil
	},
	decode: func(t *Type, b []byte) (any, error) { return Step{Increase: b[0]&8 != 0, StepCode: b[0] & 7}, nil },
	parse: func(t *Type, s string) (any, error) {
		// "+3" increase step code 3, "-1" decrease, "stop" break.
		if strings.EqualFold(s, "stop") || strings.EqualFold(s, "break") {
			return Step{}, nil
		}
		if len(s) < 2 || (s[0] != '+' && s[0] != '-') {
			return nil, errValue("%q: want +N, -N (N 1..7) or stop", s)
		}
		n, err := strconv.ParseUint(s[1:], 10, 8)
		if err != nil || n > 7 {
			return nil, errValue("%q: want +N, -N (N 0..7) or stop", s)
		}
		return Step{Increase: s[0] == '+', StepCode: uint8(n)}, nil
	},
	format: func(t *Type, v any) (string, bool) {
		s, ok := v.(Step)
		if !ok {
			return "", false
		}
		if s.StepCode == 0 {
			return "stop", true
		}
		d := "-"
		if s.Increase {
			d = "+"
		}
		return fmt.Sprintf("%s%d", d, s.StepCode), true
	},
}

// ---- DPT 4 and 16: characters and strings ----

func encodeText(t *Type, s string, n int) ([]byte, error) {
	out := make([]byte, 0, n)
	for _, r := range s {
		if r == 0 {
			// NUL terminates the text; Decode rejects data after it.
			return nil, errValue("NUL character in text of %s", t.ID)
		}
		if r > 0xFF || (t.ID.Sub == 0 && t.ID.Main == 16 && r > 0x7F) || (t.ID.Main == 4 && t.ID.Sub == 1 && r > 0x7F) {
			return nil, errValue("character %q is not in the character set of %s", r, t.ID)
		}
		out = append(out, byte(r))
	}
	if len(out) > n {
		return nil, errValue("%d characters, at most %d", len(out), n)
	}
	for len(out) < n {
		out = append(out, 0)
	}
	return out, nil
}

func decodeText(t *Type, b []byte) (string, error) {
	var sb strings.Builder
	for i, c := range b {
		if c == 0 {
			// Characters after the terminating NUL must be NUL too.
			for _, d := range b[i:] {
				if d != 0 {
					return "", errValue("non-NUL octet after NUL")
				}
			}
			break
		}
		if c > 0x7F && (t.ID.Sub == 0 && t.ID.Main == 16 || t.ID.Main == 4 && t.ID.Sub == 1) {
			return "", errValue("octet 0x%02X is not ASCII", c)
		}
		sb.WriteRune(rune(c))
	}
	return sb.String(), nil
}

// unquoteText undoes the quoting of Format for DPT 4 and 16 text.
func unquoteText(s string) string {
	if len(s) >= 2 && s[0] == '"' {
		if u, err := strconv.Unquote(s); err == nil {
			return u
		}
	}
	return s
}

var charCodec = codec{
	encode: func(t *Type, v any) ([]byte, error) {
		s, ok := v.(string)
		if !ok {
			return nil, errValue("%v (%T) is not a string", v, v)
		}
		if s == "" {
			// NUL, which Decode returns as "".
			return []byte{0}, nil
		}
		if utf8.RuneCountInString(s) != 1 {
			return nil, errValue("%q is not one character", s)
		}
		return encodeText(t, s, 1)
	},
	decode: func(t *Type, b []byte) (any, error) {
		if b[0] == 0 {
			return "", nil
		}
		return decodeText(t, b)
	},
	parse: func(t *Type, s string) (any, error) { return unquoteText(s), nil },
	format: func(t *Type, v any) (string, bool) {
		s, ok := v.(string)
		return strconv.Quote(s), ok
	},
}

var stringCodec = codec{
	encode: func(t *Type, v any) ([]byte, error) {
		s, ok := v.(string)
		if !ok {
			return nil, errValue("%v (%T) is not a string", v, v)
		}
		return encodeText(t, s, 14)
	},
	decode: func(t *Type, b []byte) (any, error) { return decodeText(t, b) },
	parse:  func(t *Type, s string) (any, error) { return unquoteText(s), nil },
	format: func(t *Type, v any) (string, bool) {
		s, ok := v.(string)
		return strconv.Quote(s), ok
	},
}

// ---- integers: DPT 5, 6, 7, 8, 12, 13, 29 (scale 1) ----

// intCodec handles an n-octet integer, signed or not, whose value is the
// raw number times scale. Scale 1 decodes to uint64 or int64, other
// scales to float64.
func intCodec(octets int, signed bool, scale float64) codec {
	bits := uint(octets * 8)
	var lo, hi float64
	if signed {
		lo, hi = -math.Ldexp(1, int(bits-1)), math.Ldexp(1, int(bits-1))-1
	} else {
		lo, hi = 0, math.Ldexp(1, int(bits))-1
	}
	put := func(raw int64) []byte {
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(raw))
		return b[8-octets:]
	}
	get := func(b []byte) int64 {
		var u uint64
		for _, c := range b {
			u = u<<8 | uint64(c)
		}
		if signed && bits < 64 && u&(1<<(bits-1)) != 0 {
			u |= ^uint64(0) << bits
		}
		return int64(u)
	}
	return codec{
		encode: func(t *Type, v any) ([]byte, error) {
			if scale == 1 {
				if !signed {
					if u, ok := v.(uint64); ok {
						if float64(u) > hi || (t.HasRange && float64(u) > t.Max) {
							return nil, errValue("%d out of range", u)
						}
						return put(int64(u)), nil
					}
				}
				n, err := toInt(v)
				if err != nil {
					return nil, err
				}
				if float64(n) < lo || float64(n) > hi {
					return nil, errValue("%d out of range %.0f..%.0f", n, lo, hi)
				}
				if err := checkRange(t, float64(n)); err != nil {
					return nil, err
				}
				return put(n), nil
			}
			f, err := toFloat(v)
			if err != nil {
				return nil, err
			}
			if err := checkRange(t, f); err != nil {
				return nil, err
			}
			raw := math.Round(f / scale)
			if raw < lo || raw > hi {
				return nil, errValue("%v out of range", f)
			}
			return put(int64(raw)), nil
		},
		decode: func(t *Type, b []byte) (any, error) {
			raw := get(b)
			if scale == 1 {
				if signed {
					return raw, nil
				}
				return uint64(raw), nil
			}
			return float64(raw) * scale, nil
		},
		parse: func(t *Type, s string) (any, error) {
			if scale == 1 {
				if signed {
					n, err := strconv.ParseInt(s, 0, 64)
					if err != nil {
						return nil, errValue("%q is not an integer", s)
					}
					return n, nil
				}
				n, err := strconv.ParseUint(s, 0, 64)
				if err != nil {
					return nil, errValue("%q is not an unsigned integer", s)
				}
				return n, nil
			}
			f, err := strconv.ParseFloat(s, 64)
			if err != nil {
				return nil, errValue("%q is not a number", s)
			}
			return f, nil
		},
	}
}

// ratioCodec is a one-octet unsigned value mapped linearly to 0..max
// (DPT 5.001 scaling 0..100 %, 5.003 angle 0..360°).
func ratioCodec(max float64) codec {
	return codec{
		encode: func(t *Type, v any) ([]byte, error) {
			f, err := toFloat(v)
			if err != nil {
				return nil, err
			}
			if err := checkRange(t, f); err != nil {
				return nil, err
			}
			return []byte{byte(math.Round(f * 255 / max))}, nil
		},
		decode: func(t *Type, b []byte) (any, error) { return float64(b[0]) * max / 255, nil },
		parse:  parseFloat,
		format: func(t *Type, v any) (string, bool) {
			f, ok := v.(float64)
			if !ok {
				return "", false
			}
			return strconv.FormatFloat(f, 'f', 1, 64) + " " + t.Unit, true
		},
	}
}

func parseFloat(t *Type, s string) (any, error) {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil, errValue("%q is not a number", s)
	}
	return f, nil
}

// ---- DPT 9: 2-octet float ----

// Float16Max is the largest DPT 9 value that can be encoded: mantissa 2046,
// exponent 15 (0x7FFF, mantissa 2047, means "invalid data").
const Float16Max = 670433.28

// Float16Min is the smallest DPT 9 value: mantissa -2048, exponent 15.
const Float16Min = -671088.64

// EncodeFloat16 encodes f in the KNX 2-octet float format: 0.01·M·2^E with
// a 12-bit two's complement mantissa M and a 4-bit exponent E, choosing
// the smallest exponent that fits, mantissa rounded to nearest (half away
// from zero).
func EncodeFloat16(f float64) (uint16, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) || f < Float16Min || f > Float16Max {
		return 0, errValue("%v out of the 2-octet float range %v..%v", f, Float16Min, Float16Max)
	}
	v := f * 100
	for e := 0; e <= 15; e++ {
		m := math.Round(v / math.Ldexp(1, e))
		if m >= -2048 && m <= 2047 {
			raw := uint16(e)<<11 | uint16(int16(m))&0x07FF
			if m < 0 {
				raw |= 0x8000
			}
			if raw == 0x7FFF {
				return 0, errValue("%v encodes to 0x7FFF (invalid data)", f)
			}
			return raw, nil
		}
	}
	return 0, errValue("%v out of the 2-octet float range", f)
}

// ErrFloat16Invalid is the error of decoding 0x7FFF, the DPT 9 "invalid
// data" value.
var ErrFloat16Invalid = errValue("0x7FFF: invalid data")

// DecodeFloat16 decodes the KNX 2-octet float format.
func DecodeFloat16(raw uint16) (float64, error) {
	if raw == 0x7FFF {
		return 0, ErrFloat16Invalid
	}
	m := int(raw & 0x07FF)
	if raw&0x8000 != 0 {
		m -= 2048
	}
	e := int(raw>>11) & 0x0F
	return float64(m) * math.Ldexp(1, e) / 100, nil
}

var float16Codec = codec{
	encode: func(t *Type, v any) ([]byte, error) {
		f, err := toFloat(v)
		if err != nil {
			return nil, err
		}
		if err := checkRange(t, f); err != nil {
			return nil, err
		}
		raw, err := EncodeFloat16(f)
		if err != nil {
			return nil, err
		}
		return []byte{byte(raw >> 8), byte(raw)}, nil
	},
	decode: func(t *Type, b []byte) (any, error) { return DecodeFloat16(binary.BigEndian.Uint16(b)) },
	parse:  parseFloat,
}

// ---- DPT 14: 4-octet IEEE 754 float ----

var float32Codec = codec{
	encode: func(t *Type, v any) ([]byte, error) {
		f, err := toFloat(v)
		if err != nil {
			return nil, err
		}
		if err := checkRange(t, f); err != nil {
			return nil, err
		}
		// Not math.MaxFloat32: Decode returns its shortest decimal,
		// 3.4028235e38, which is slightly larger but rounds to it.
		if math.IsInf(float64(float32(f)), 0) {
			return nil, errValue("%v out of the float32 range", f)
		}
		return binary.BigEndian.AppendUint32(nil, math.Float32bits(float32(f))), nil
	},
	decode: func(t *Type, b []byte) (any, error) {
		f := math.Float32frombits(binary.BigEndian.Uint32(b))
		if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
			return nil, errValue("not a finite number (0x%08X)", binary.BigEndian.Uint32(b))
		}
		// The shortest decimal of the float32, not of its float64 widening.
		v, _ := strconv.ParseFloat(strconv.FormatFloat(float64(f), 'g', -1, 32), 64)
		return v, nil
	},
	parse: parseFloat,
}

// ---- DPT 10: time of day ----

var timeCodec = codec{
	encode: func(t *Type, v any) ([]byte, error) {
		x, ok := v.(TimeOfDay)
		if !ok {
			return nil, errValue("%v (%T) is not a dpt.TimeOfDay", v, v)
		}
		if x.Weekday > 7 || x.Hour > 23 || x.Minute > 59 || x.Second > 59 {
			return nil, errValue("time %v out of range", x)
		}
		return []byte{x.Weekday<<5 | x.Hour, x.Minute, x.Second}, nil
	},
	decode: func(t *Type, b []byte) (any, error) {
		x := TimeOfDay{Weekday: b[0] >> 5, Hour: b[0] & 0x1F, Minute: b[1], Second: b[2]}
		if x.Hour > 23 || x.Minute > 59 || x.Second > 59 {
			return nil, errValue("time %02d:%02d:%02d out of range", x.Hour, x.Minute, x.Second)
		}
		return x, nil
	},
	parse: func(t *Type, s string) (any, error) {
		var x TimeOfDay
		if i := strings.IndexByte(s, ' '); i > 0 {
			d := strings.ToLower(s[:i])
			for n, w := range weekdays {
				if n > 0 && strings.EqualFold(w, d) {
					x.Weekday = uint8(n)
				}
			}
			if x.Weekday == 0 {
				return nil, errValue("%q: unknown day (Mon..Sun)", s[:i])
			}
			s = s[i+1:]
		}
		h, m, sec, err := parseClock(s)
		if err != nil || h > 23 {
			return nil, errValue("%q: want [Mon..Sun] HH:MM[:SS]", s)
		}
		x.Hour, x.Minute, x.Second = h, m, sec
		return x, nil
	},
	format: func(t *Type, v any) (string, bool) {
		x, ok := v.(TimeOfDay)
		return x.String(), ok
	},
}

func parseClock(s string) (h, m, sec uint8, err error) {
	parts := strings.Split(s, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return 0, 0, 0, errValue("%q", s)
	}
	var v [3]uint64
	for i, p := range parts {
		n, e := strconv.ParseUint(p, 10, 8)
		if e != nil {
			return 0, 0, 0, errValue("%q", s)
		}
		v[i] = n
	}
	if v[1] > 59 || v[2] > 59 {
		return 0, 0, 0, errValue("%q", s)
	}
	return uint8(v[0]), uint8(v[1]), uint8(v[2]), nil
}

// ---- DPT 11: date ----

var dateCodec = codec{
	encode: func(t *Type, v any) ([]byte, error) {
		d, ok := v.(Date)
		if !ok {
			return nil, errValue("%v (%T) is not a dpt.Date", v, v)
		}
		if d.Year < 1990 || d.Year > 2089 || d.Month < 1 || d.Month > 12 || d.Day < 1 || d.Day > 31 {
			return nil, errValue("date %v out of range 1990-01-01..2089-12-31", d)
		}
		return []byte{d.Day, d.Month, byte(d.Year % 100)}, nil
	},
	decode: func(t *Type, b []byte) (any, error) {
		d := Date{Day: b[0], Month: b[1]}
		y := int(b[2])
		if d.Day < 1 || d.Day > 31 || d.Month < 1 || d.Month > 12 || y > 99 || b[0]&0xE0 != 0 || b[1]&0xF0 != 0 {
			return nil, errValue("date % X out of range", b)
		}
		// Years 90..99 are 1990..1999, 0..89 are 2000..2089.
		if y >= 90 {
			d.Year = 1900 + y
		} else {
			d.Year = 2000 + y
		}
		return d, nil
	},
	parse: func(t *Type, s string) (any, error) {
		y, m, d, err := parseYMD(s)
		if err != nil {
			return nil, err
		}
		return Date{Year: y, Month: m, Day: d}, nil
	},
	format: func(t *Type, v any) (string, bool) {
		d, ok := v.(Date)
		return d.String(), ok
	},
}

func parseYMD(s string) (int, uint8, uint8, error) {
	parts := strings.Split(s, "-")
	if len(parts) != 3 {
		return 0, 0, 0, errValue("%q: want YYYY-MM-DD", s)
	}
	y, e1 := strconv.Atoi(parts[0])
	m, e2 := strconv.ParseUint(parts[1], 10, 8)
	d, e3 := strconv.ParseUint(parts[2], 10, 8)
	if e1 != nil || e2 != nil || e3 != nil {
		return 0, 0, 0, errValue("%q: want YYYY-MM-DD", s)
	}
	return y, uint8(m), uint8(d), nil
}

// ---- DPT 17, 18, 26: scenes ----

var sceneCodec = codec{
	encode: func(t *Type, v any) ([]byte, error) {
		n, err := toInt(v)
		if err != nil {
			return nil, err
		}
		if n < 0 || n > 63 {
			return nil, errValue("scene %d out of range 0..63", n)
		}
		return []byte{byte(n)}, nil
	},
	decode: func(t *Type, b []byte) (any, error) {
		if b[0] > 63 {
			return nil, errValue("scene octet 0x%02X: reserved bits set", b[0])
		}
		return b[0], nil
	},
	parse: func(t *Type, s string) (any, error) {
		n, err := strconv.ParseUint(s, 10, 8)
		if err != nil {
			return nil, errValue("%q is not a scene number", s)
		}
		return uint8(n), nil
	},
}

var sceneControlCodec = codec{
	encode: func(t *Type, v any) ([]byte, error) {
		c, ok := v.(SceneControl)
		if !ok {
			return nil, errValue("%v (%T) is not a dpt.SceneControl", v, v)
		}
		if c.Scene > 63 {
			return nil, errValue("scene %d out of range 0..63", c.Scene)
		}
		b := c.Scene
		if c.Learn {
			b |= 0x80
		}
		return []byte{b}, nil
	},
	decode: func(t *Type, b []byte) (any, error) {
		if b[0]&0x40 != 0 {
			return nil, errValue("scene control octet 0x%02X: reserved bit set", b[0])
		}
		return SceneControl{Learn: b[0]&0x80 != 0, Scene: b[0] & 0x3F}, nil
	},
	parse: func(t *Type, s string) (any, error) {
		learn := false
		if rest, ok := strings.CutPrefix(strings.ToLower(s), "learn "); ok {
			learn, s = true, rest
		} else if rest, ok := strings.CutPrefix(strings.ToLower(s), "activate "); ok {
			s = rest
		}
		n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 8)
		if err != nil || n > 63 {
			return nil, errValue("%q: want [learn|activate] 0..63", s)
		}
		return SceneControl{Learn: learn, Scene: uint8(n)}, nil
	},
	format: func(t *Type, v any) (string, bool) {
		c, ok := v.(SceneControl)
		if !ok {
			return "", false
		}
		if c.Learn {
			return fmt.Sprintf("learn %d", c.Scene), true
		}
		return fmt.Sprintf("activate %d", c.Scene), true
	},
}

// ---- DPT 19: date and time ----

var dateTimeCodec = codec{
	encode: func(t *Type, v any) ([]byte, error) {
		d, ok := v.(DateTime)
		if !ok {
			return nil, errValue("%v (%T) is not a dpt.DateTime", v, v)
		}
		// Fields flagged invalid (ND, NT) need only fit their bits, as
		// Decode accepts them.
		badDate := d.Month > 15 || d.Day > 31 || (!d.NoDate && (d.Month < 1 || d.Month > 12 || d.Day < 1))
		badTime := d.Hour > 31 || d.Minute > 63 || d.Second > 63 ||
			(!d.NoTime && (d.Hour > 24 || d.Minute > 59 || d.Second > 59 || (d.Hour == 24 && (d.Minute != 0 || d.Second != 0))))
		if d.Year < 1900 || d.Year > 2155 || d.Weekday > 7 || badDate || badTime {
			return nil, errValue("date and time %v out of range", d)
		}
		f := flagBits(d.Fault, d.WorkingDay, d.NoWorkingDay, d.NoYear, d.NoDate, d.NoWeekday, d.NoTime, d.SummerTime)
		q := flagBits(d.ExternalSync, d.ReliableSource)
		return []byte{byte(d.Year - 1900), d.Month, d.Day, d.Weekday<<5 | d.Hour, d.Minute, d.Second, f, q}, nil
	},
	decode: func(t *Type, b []byte) (any, error) {
		d := DateTime{
			Year: 1900 + int(b[0]), Month: b[1], Day: b[2], Weekday: b[3] >> 5, Hour: b[3] & 0x1F, Minute: b[4], Second: b[5],
			Fault: b[6]&0x80 != 0, WorkingDay: b[6]&0x40 != 0, NoWorkingDay: b[6]&0x20 != 0, NoYear: b[6]&0x10 != 0,
			NoDate: b[6]&0x08 != 0, NoWeekday: b[6]&0x04 != 0, NoTime: b[6]&0x02 != 0, SummerTime: b[6]&0x01 != 0,
			ExternalSync: b[7]&0x80 != 0, ReliableSource: b[7]&0x40 != 0,
		}
		if b[1]&0xF0 != 0 || b[2]&0xE0 != 0 || b[4]&0xC0 != 0 || b[5]&0xC0 != 0 {
			return nil, errValue("date and time % X: reserved bits set", b)
		}
		if !d.NoDate && (d.Month < 1 || d.Month > 12 || d.Day < 1 || d.Day > 31) {
			return nil, errValue("date %02d-%02d out of range", d.Month, d.Day)
		}
		if !d.NoTime && (d.Hour > 24 || d.Minute > 59 || d.Second > 59 || (d.Hour == 24 && (d.Minute != 0 || d.Second != 0))) {
			return nil, errValue("time %02d:%02d:%02d out of range", d.Hour, d.Minute, d.Second)
		}
		return d, nil
	},
	parse: func(t *Type, s string) (any, error) {
		ds, ts, ok := strings.Cut(strings.Replace(s, "T", " ", 1), " ")
		if !ok {
			return nil, errValue("%q: want YYYY-MM-DD HH:MM:SS", s)
		}
		y, m, d, err := parseYMD(ds)
		if err != nil {
			return nil, err
		}
		h, mi, sec, err := parseClock(ts)
		if err != nil {
			return nil, errValue("%q: want YYYY-MM-DD HH:MM:SS", s)
		}
		return DateTime{Year: y, Month: m, Day: d, Hour: h, Minute: mi, Second: sec, NoWeekday: true, NoWorkingDay: true}, nil
	},
	format: func(t *Type, v any) (string, bool) {
		d, ok := v.(DateTime)
		return d.String(), ok
	},
}

func flagBits(fs ...bool) byte {
	var b byte
	for i, f := range fs {
		if f {
			b |= 0x80 >> i
		}
	}
	return b
}

// ---- DPT 20: enumerations ----

var enumCodec = codec{
	encode: func(t *Type, v any) ([]byte, error) {
		var n uint8
		switch x := v.(type) {
		case Enum:
			n = x.Value
		case string:
			found := false
			for k, name := range t.Enum {
				if strings.EqualFold(name, x) {
					n, found = k, true
				}
			}
			if !found {
				return nil, errValue("%q is not a value of %s", x, t.ID)
			}
		default:
			i, err := toInt(v)
			if err != nil || i < 0 || i > 255 {
				return nil, errValue("%v is not a value of %s", v, t.ID)
			}
			n = uint8(i)
		}
		if t.Enum != nil {
			if _, ok := t.Enum[n]; !ok {
				return nil, errValue("%d is not a value of %s", n, t.ID)
			}
		}
		return []byte{n}, nil
	},
	decode: func(t *Type, b []byte) (any, error) {
		if t.Enum == nil {
			return Enum{Value: b[0]}, nil
		}
		name, ok := t.Enum[b[0]]
		if !ok {
			return nil, errValue("%d is not a value of %s", b[0], t.ID)
		}
		return Enum{Value: b[0], Name: name}, nil
	},
	parse: func(t *Type, s string) (any, error) {
		if n, err := strconv.ParseUint(s, 10, 8); err == nil {
			return Enum{Value: uint8(n), Name: t.Enum[uint8(n)]}, nil
		}
		for k, name := range t.Enum {
			if strings.EqualFold(name, s) {
				return Enum{Value: k, Name: name}, nil
			}
		}
		return nil, errValue("%q is not a value of %s", s, t.ID)
	},
	format: func(t *Type, v any) (string, bool) {
		e, ok := v.(Enum)
		return e.String(), ok
	},
}

// ---- DPT 21, 22: bit sets ----

func bitsCodec(octets int) codec {
	return codec{
		encode: func(t *Type, v any) ([]byte, error) {
			n, err := toInt(v)
			if err != nil || n < 0 || n >= 1<<(8*octets) {
				return nil, errValue("%v is not a %d-bit set", v, 8*octets)
			}
			b := make([]byte, 8)
			binary.BigEndian.PutUint64(b, uint64(n))
			return b[8-octets:], nil
		},
		decode: func(t *Type, b []byte) (any, error) {
			var u uint64
			for _, c := range b {
				u = u<<8 | uint64(c)
			}
			return u, nil
		},
		parse: func(t *Type, s string) (any, error) {
			n, err := strconv.ParseUint(s, 0, 8*octets)
			if err != nil {
				return nil, errValue("%q is not a %d-bit set (0b..., 0x... or decimal)", s, 8*octets)
			}
			return n, nil
		},
		format: func(t *Type, v any) (string, bool) {
			u, ok := v.(uint64)
			return fmt.Sprintf("0b%0*b", 8*octets, u), ok
		},
	}
}

// ---- DPT 232.600, 251.600, 242.600: colours ----

func parseHex(s string, n int) ([]byte, error) {
	s = strings.TrimPrefix(s, "#")
	if len(s) != 2*n {
		return nil, errValue("%q: want #%s", s, strings.Repeat("XX", n))
	}
	out := make([]byte, n)
	for i := range out {
		v, err := strconv.ParseUint(s[2*i:2*i+2], 16, 8)
		if err != nil {
			return nil, errValue("%q: want #%s", s, strings.Repeat("XX", n))
		}
		out[i] = byte(v)
	}
	return out, nil
}

var rgbCodec = codec{
	encode: func(t *Type, v any) ([]byte, error) {
		c, ok := v.(RGB)
		if !ok {
			return nil, errValue("%v (%T) is not a dpt.RGB", v, v)
		}
		return []byte{c.R, c.G, c.B}, nil
	},
	decode: func(t *Type, b []byte) (any, error) { return RGB{R: b[0], G: b[1], B: b[2]}, nil },
	parse: func(t *Type, s string) (any, error) {
		b, err := parseHex(s, 3)
		if err != nil {
			return nil, err
		}
		return RGB{R: b[0], G: b[1], B: b[2]}, nil
	},
	format: func(t *Type, v any) (string, bool) { c, ok := v.(RGB); return c.String(), ok },
}

var rgbwCodec = codec{
	encode: func(t *Type, v any) ([]byte, error) {
		c, ok := v.(RGBW)
		if !ok {
			return nil, errValue("%v (%T) is not a dpt.RGBW", v, v)
		}
		return []byte{c.R, c.G, c.B, c.W, 0, flagBits(false, false, false, false, c.ValidR, c.ValidG, c.ValidB, c.ValidW)}, nil
	},
	decode: func(t *Type, b []byte) (any, error) {
		if b[4] != 0 || b[5]&0xF0 != 0 {
			return nil, errValue("RGBW % X: reserved bits set", b)
		}
		return RGBW{R: b[0], G: b[1], B: b[2], W: b[3], ValidR: b[5]&8 != 0, ValidG: b[5]&4 != 0, ValidB: b[5]&2 != 0, ValidW: b[5]&1 != 0}, nil
	},
	parse: func(t *Type, s string) (any, error) {
		b, err := parseHex(s, 4)
		if err != nil {
			return nil, err
		}
		return RGBW{R: b[0], G: b[1], B: b[2], W: b[3], ValidR: true, ValidG: true, ValidB: true, ValidW: true}, nil
	},
	format: func(t *Type, v any) (string, bool) { c, ok := v.(RGBW); return c.String(), ok },
}

var xyyCodec = codec{
	encode: func(t *Type, v any) ([]byte, error) {
		c, ok := v.(XYY)
		if !ok {
			return nil, errValue("%v (%T) is not a dpt.XYY", v, v)
		}
		if c.X < 0 || c.X > 1 || c.Y < 0 || c.Y > 1 || c.Brightness < 0 || c.Brightness > 100 {
			return nil, errValue("xyY %v out of range (x, y 0..1, brightness 0..100)", c)
		}
		x, y := uint16(math.Round(c.X*65535)), uint16(math.Round(c.Y*65535))
		return []byte{byte(x >> 8), byte(x), byte(y >> 8), byte(y), byte(math.Round(c.Brightness * 255 / 100)), flagBits(false, false, false, false, false, false, c.ColorValid, c.BrightnessValid)}, nil
	},
	decode: func(t *Type, b []byte) (any, error) {
		if b[5]&0xFC != 0 {
			return nil, errValue("xyY % X: reserved bits set", b)
		}
		return XYY{X: float64(binary.BigEndian.Uint16(b)) / 65535, Y: float64(binary.BigEndian.Uint16(b[2:])) / 65535,
			Brightness: float64(b[4]) * 100 / 255, ColorValid: b[5]&2 != 0, BrightnessValid: b[5]&1 != 0}, nil
	},
	parse: func(t *Type, s string) (any, error) {
		// "x,y,brightness", or Format's "x=X y=Y brightness=B %".
		if f := strings.Fields(strings.TrimSuffix(s, "%")); len(f) == 3 &&
			strings.HasPrefix(f[0], "x=") && strings.HasPrefix(f[1], "y=") && strings.HasPrefix(f[2], "brightness=") {
			s = f[0][2:] + "," + f[1][2:] + "," + f[2][len("brightness="):]
		}
		parts := strings.Split(s, ",")
		if len(parts) != 3 {
			return nil, errValue("%q: want x,y,brightness", s)
		}
		var f [3]float64
		for i, p := range parts {
			v, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
			if err != nil {
				return nil, errValue("%q: want x,y,brightness", s)
			}
			f[i] = v
		}
		return XYY{X: f[0], Y: f[1], Brightness: f[2], ColorValid: true, BrightnessValid: true}, nil
	},
	format: func(t *Type, v any) (string, bool) {
		c, ok := v.(XYY)
		return fmt.Sprintf("x=%.4f y=%.4f brightness=%.1f %%", c.X, c.Y, c.Brightness), ok
	},
}
