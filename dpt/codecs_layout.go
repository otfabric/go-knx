// SPDX-License-Identifier: MIT

package dpt

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Codecs of the composite types whose value is a struct of fixed-width
// fields: DPT 6.020, 25, 206, 219, 225, 229, 230, 232.601, 235, 236, 237,
// 238, 240, 241, 244, 245, 246, 249, 250, 252, 254, 255 and 207.600. A layout lists the fields of a
// value type V from the most significant bit of the first octet on; its
// codec packs them big endian into Type.Size octets and reads them back.
//
// As text, a value is a list of words: name=value for the numeric fields
// (in any order, a missing one is zero) and the bare name of each flag
// that is set. A value with a space is quoted: mode="building protection".

// field is one field of a layout of V.
type field[V any] struct {
	// name is the name of the field as text; empty for reserved bits,
	// which encode as 0 and must be 0 to decode.
	name string
	bits int
	// flag fields are printed as their name when set and parsed from the
	// name alone.
	flag bool
	// get returns the bits of the field of v, or an error when the value
	// does not fit the field.
	get func(t *Type, v *V) (uint64, error)
	// set stores raw in v, or returns an error when raw is not a value of
	// the field.
	set func(t *Type, v *V, raw uint64) error
	// text formats the field of v; parse sets it from text.
	text  func(v *V) string
	parse func(t *Type, v *V, s string) error
}

func reserved[V any](bits int) field[V] { return field[V]{bits: bits} }

// flagField is a 1-bit flag: true is the bit set.
func flagField[V any](name string, p func(*V) *bool) field[V] {
	return field[V]{
		name: name, bits: 1, flag: true,
		get: func(t *Type, v *V) (uint64, error) {
			if *p(v) {
				return 1, nil
			}
			return 0, nil
		},
		set:  func(t *Type, v *V, raw uint64) error { *p(v) = raw == 1; return nil },
		text: func(v *V) string { return strconv.FormatBool(*p(v)) },
		parse: func(t *Type, v *V, s string) error {
			b, err := strconv.ParseBool(s)
			if err != nil {
				return errValue("%s=%q is not a boolean", name, s)
			}
			*p(v) = b
			return nil
		},
	}
}

// unsignedField is an unsigned integer of bits bits; max, when not zero,
// is the largest value the type defines (Encode and Decode refuse more).
func unsignedField[V any, N uint8 | uint16 | uint32](name string, bits int, max uint64, p func(*V) *N) field[V] {
	if max == 0 {
		max = 1<<bits - 1
	}
	return field[V]{
		name: name, bits: bits,
		get: func(t *Type, v *V) (uint64, error) {
			if n := uint64(*p(v)); n <= max {
				return n, nil
			}
			return 0, errValue("%s %d out of range 0..%d", name, *p(v), max)
		},
		set: func(t *Type, v *V, raw uint64) error {
			if raw > max {
				return errValue("%s %d out of range 0..%d", name, raw, max)
			}
			*p(v) = N(raw)
			return nil
		},
		text: func(v *V) string { return strconv.FormatUint(uint64(*p(v)), 10) },
		parse: func(t *Type, v *V, s string) error {
			n, err := strconv.ParseUint(s, 0, bits)
			if err != nil || n > max {
				return errValue("%s=%q: want 0..%d", name, s, max)
			}
			*p(v) = N(n)
			return nil
		},
	}
}

// scaledField is an unsigned integer of bits bits counting steps of scale:
// a time period in milliseconds sent in steps of 100 ms. Encode refuses a
// value that is not a whole number of steps.
func scaledField[V any](name string, bits int, scale uint32, p func(*V) *uint32) field[V] {
	max := uint64(1)<<bits - 1
	return field[V]{
		name: name, bits: bits,
		get: func(t *Type, v *V) (uint64, error) {
			n := *p(v)
			if n%scale != 0 || uint64(n/scale) > max {
				return 0, errValue("%s %d is not a multiple of %d up to %d", name, n, scale, max*uint64(scale))
			}
			return uint64(n / scale), nil
		},
		set:  func(t *Type, v *V, raw uint64) error { *p(v) = uint32(raw) * scale; return nil },
		text: func(v *V) string { return strconv.FormatUint(uint64(*p(v)), 10) },
		parse: func(t *Type, v *V, s string) error {
			n, err := strconv.ParseUint(s, 10, 32)
			if err != nil {
				return errValue("%s=%q is not an unsigned integer", name, s)
			}
			*p(v) = uint32(n)
			return nil
		},
	}
}

// signedField is a 4-octet two's complement integer.
func signedField[V any](name string, p func(*V) *int32) field[V] {
	return field[V]{
		name: name, bits: 32,
		get:  func(t *Type, v *V) (uint64, error) { return uint64(uint32(*p(v))), nil },
		set:  func(t *Type, v *V, raw uint64) error { *p(v) = int32(uint32(raw)); return nil },
		text: func(v *V) string { return strconv.FormatInt(int64(*p(v)), 10) },
		parse: func(t *Type, v *V, s string) error {
			n, err := strconv.ParseInt(s, 10, 32)
			if err != nil {
				return errValue("%s=%q is not a 32-bit integer", name, s)
			}
			*p(v) = int32(n)
			return nil
		},
	}
}

// ratioField is one octet mapped linearly to 0..max, as DPT 5.001
// (percentage, max 100) and 5.003 (angle, max 360).
func ratioField[V any](name string, max float64, p func(*V) *float64) field[V] {
	return field[V]{
		name: name, bits: 8,
		get: func(t *Type, v *V) (uint64, error) {
			f := *p(v)
			if !(f >= 0 && f <= max) {
				return 0, errValue("%s %v out of range 0..%v", name, f, max)
			}
			return uint64(math.Round(f * 255 / max)), nil
		},
		set:  func(t *Type, v *V, raw uint64) error { *p(v) = float64(raw) * max / 255; return nil },
		text: func(v *V) string { return strconv.FormatFloat(*p(v), 'f', 1, 64) },
		parse: func(t *Type, v *V, s string) error {
			f, err := strconv.ParseFloat(s, 64)
			if err != nil {
				return errValue("%s=%q is not a number", name, s)
			}
			*p(v) = f
			return nil
		},
	}
}

// float32Field is a 4-octet IEEE 754 float; NaN and the infinities are
// refused both ways, as in DPT 14.
func float32Field[V any](name string, p func(*V) *float64) field[V] {
	return field[V]{
		name: name, bits: 32,
		get: func(t *Type, v *V) (uint64, error) {
			f := *p(v)
			if math.IsNaN(f) || math.IsInf(float64(float32(f)), 0) {
				return 0, errValue("%s %v is not a finite float32", name, f)
			}
			return uint64(math.Float32bits(float32(f))), nil
		},
		set: func(t *Type, v *V, raw uint64) error {
			f := math.Float32frombits(uint32(raw))
			if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
				return errValue("%s is not a finite number (0x%08X)", name, raw)
			}
			// The shortest decimal of the float32, not of its float64
			// widening.
			*p(v), _ = strconv.ParseFloat(strconv.FormatFloat(float64(f), 'g', -1, 32), 64)
			return nil
		},
		text: func(v *V) string { return strconv.FormatFloat(*p(v), 'g', -1, 64) },
		parse: func(t *Type, v *V, s string) error {
			f, err := strconv.ParseFloat(s, 64)
			if err != nil {
				return errValue("%s=%q is not a number", name, s)
			}
			*p(v) = f
			return nil
		},
	}
}

// stepField is a DPT 3 step in 4 bits: the direction and a step code.
func stepField[V any](name string, p func(*V) *Step) field[V] {
	return field[V]{
		name: name, bits: 4,
		get: func(t *Type, v *V) (uint64, error) {
			b, err := stepCodec.encode(t, *p(v))
			if err != nil {
				return 0, fmt.Errorf("%s: %w", name, err)
			}
			return uint64(b[0]), nil
		},
		set: func(t *Type, v *V, raw uint64) error {
			*p(v) = Step{Increase: raw&8 != 0, StepCode: uint8(raw & 7)}
			return nil
		},
		text: func(v *V) string { s, _ := stepCodec.format(nil, *p(v)); return s },
		parse: func(t *Type, v *V, s string) error {
			x, err := stepCodec.parse(t, s)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			*p(v) = x.(Step)
			return nil
		},
	}
}

// enumField is an 8-bit enumeration whose names are those of the type
// (Type.Enum); without names every value is accepted.
func enumField[V any](name string, p func(*V) *Enum) field[V] {
	return field[V]{
		name: name, bits: 8,
		get: func(t *Type, v *V) (uint64, error) {
			n := p(v).Value
			if _, ok := t.Enum[n]; t.Enum != nil && !ok {
				return 0, errValue("%s %d is not a value of %s", name, n, t.ID)
			}
			return uint64(n), nil
		},
		set: func(t *Type, v *V, raw uint64) error {
			n, ok := t.Enum[uint8(raw)]
			if t.Enum != nil && !ok {
				return errValue("%s %d is not a value of %s", name, raw, t.ID)
			}
			*p(v) = Enum{Value: uint8(raw), Name: n}
			return nil
		},
		text: func(v *V) string { return p(v).String() },
		parse: func(t *Type, v *V, s string) error {
			e, err := enumCodec.parse(t, s)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			*p(v) = e.(Enum)
			return nil
		},
	}
}

// layoutCodec returns the codec of a layout. The fields must add up to the
// bits of the types that use it, at most 64.
func layoutCodec[V any](fields []field[V]) codec {
	total := 0
	widths := make([]int, len(fields))
	for i, f := range fields {
		total += f.bits
		widths[i] = f.bits
		if f.name == "" {
			widths[i] = -f.bits
		}
	}
	if total > 64 || total%8 != 0 {
		panic(fmt.Sprintf("dpt: layout of %T has %d bits", *new(V), total))
	}
	return codec{
		layout: widths,
		encode: func(t *Type, v any) ([]byte, error) {
			x, ok := v.(V)
			if !ok {
				return nil, errValue("%v (%T) is not a %T", v, v, x)
			}
			var acc uint64
			for _, f := range fields {
				var raw uint64
				if f.get != nil {
					r, err := f.get(t, &x)
					if err != nil {
						return nil, err
					}
					raw = r
				}
				acc = acc<<f.bits | raw
			}
			b := binary.BigEndian.AppendUint64(nil, acc)
			return b[8-total/8:], nil
		},
		decode: func(t *Type, b []byte) (any, error) {
			var acc uint64
			for _, c := range b {
				acc = acc<<8 | uint64(c)
			}
			var x V
			at := total
			for _, f := range fields {
				at -= f.bits
				raw := acc >> at & (1<<f.bits - 1)
				if f.set == nil {
					if raw != 0 {
						return nil, errValue("% X: reserved bits set", b)
					}
					continue
				}
				if err := f.set(t, &x, raw); err != nil {
					return nil, err
				}
			}
			return x, nil
		},
		parse: func(t *Type, s string) (any, error) {
			var x V
			words, err := splitWords(s)
			if err != nil {
				return nil, err
			}
		next:
			for _, w := range words {
				name, val, hasVal := strings.Cut(w, "=")
				for _, f := range fields {
					if f.name == "" || !strings.EqualFold(f.name, name) {
						continue
					}
					switch {
					case hasVal:
						if u, err := strconv.Unquote(val); err == nil {
							val = u
						}
						if err := f.parse(t, &x, val); err != nil {
							return nil, err
						}
					case f.flag:
						if err := f.parse(t, &x, "true"); err != nil {
							return nil, err
						}
					default:
						return nil, errValue("%q: want %s=value", w, f.name)
					}
					continue next
				}
				return nil, errValue("%q: unknown field (want %s)", w, fieldNames(fields))
			}
			return x, nil
		},
		format: func(t *Type, v any) (string, bool) {
			x, ok := v.(V)
			if !ok {
				return "", false
			}
			return formatFields(fields, &x), true
		},
	}
}

// formatFields writes the fields of x as Parse reads them.
func formatFields[V any](fields []field[V], x *V) string {
	var words []string
	for _, f := range fields {
		switch {
		case f.name == "":
		case f.flag:
			if f.text(x) == "true" {
				words = append(words, f.name)
			}
		default:
			s := f.text(x)
			if strings.ContainsAny(s, " \"=") {
				s = strconv.Quote(s)
			}
			words = append(words, f.name+"="+s)
		}
	}
	return strings.Join(words, " ")
}

func fieldNames[V any](fields []field[V]) string {
	var names []string
	for _, f := range fields {
		if f.name != "" {
			names = append(names, f.name)
		}
	}
	return strings.Join(names, ", ")
}

// splitWords splits s at spaces outside double quotes.
func splitWords(s string) ([]string, error) {
	var words []string
	var cur strings.Builder
	quoted, escaped := false, false
	for _, r := range s {
		switch {
		case escaped:
			escaped = false
		case quoted && r == '\\':
			escaped = true
		case r == '"':
			quoted = !quoted
		case !quoted && (r == ' ' || r == '\t'):
			if cur.Len() > 0 {
				words = append(words, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteRune(r)
	}
	if quoted {
		return nil, errValue("%q: unterminated quote", s)
	}
	if cur.Len() > 0 {
		words = append(words, cur.String())
	}
	return words, nil
}

// modeNextCodec is the codec of DPT 206.
var modeNextCodec = layoutCodec(modeNextFields)
