// SPDX-License-Identifier: MIT

package dpt

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// Codecs of the composite types: DPT 15 (access data), 27 (combined
// on/off information), 217 (version), 222 and 275 (room setpoint sets) and
// 234 (two-letter codes).

// ---- DPT 15: access data ----

var accessCodec = codec{
	encode: func(t *Type, v any) ([]byte, error) {
		a, ok := v.(AccessData)
		if !ok {
			return nil, errValue("%v (%T) is not a dpt.AccessData", v, v)
		}
		if a.Code > 999999 || a.Index > 15 {
			return nil, errValue("access data %v out of range (code 0..999999, index 0..15)", a)
		}
		// Six BCD digits, the most significant in the high nibble of the
		// first octet.
		var b [4]byte
		c := a.Code
		for i := 5; i >= 0; i-- {
			d := byte(c % 10)
			c /= 10
			if i%2 == 1 {
				b[i/2] |= d
			} else {
				b[i/2] |= d << 4
			}
		}
		b[3] = flagBits(a.Error, a.Permission, a.RightToLeft, a.Encrypted) | a.Index
		return b[:], nil
	},
	decode: func(t *Type, b []byte) (any, error) {
		var code uint32
		for i := range 3 {
			hi, lo := b[i]>>4, b[i]&0x0F
			if hi > 9 || lo > 9 {
				return nil, errValue("access data % X: digit is not BCD", b)
			}
			code = code*100 + uint32(hi)*10 + uint32(lo)
		}
		return AccessData{Code: code, Error: b[3]&0x80 != 0, Permission: b[3]&0x40 != 0,
			RightToLeft: b[3]&0x20 != 0, Encrypted: b[3]&0x10 != 0, Index: b[3] & 0x0F}, nil
	},
	parse: func(t *Type, s string) (any, error) {
		// "012345", optionally followed by "index=N" and flag names, as
		// Format writes it.
		f := strings.Fields(s)
		if len(f) == 0 || len(f[0]) > 6 {
			return nil, errValue("%q: want a code of up to 6 digits [index=N] [error] [permission] [right-to-left] [encrypted]", s)
		}
		n, err := strconv.ParseUint(f[0], 10, 32)
		if err != nil {
			return nil, errValue("%q: want a code of up to 6 digits", s)
		}
		a := AccessData{Code: uint32(n)}
		flags := [...]*bool{&a.Error, &a.Permission, &a.RightToLeft, &a.Encrypted}
	next:
		for _, w := range f[1:] {
			if x, ok := strings.CutPrefix(w, "index="); ok {
				i, err := strconv.ParseUint(x, 10, 4)
				if err != nil {
					return nil, errValue("%q: index 0..15", w)
				}
				a.Index = uint8(i)
				continue
			}
			for i, name := range accessFlags {
				if strings.EqualFold(w, name) {
					*flags[i] = true
					continue next
				}
			}
			return nil, errValue("%q: unknown access data field", w)
		}
		return a, nil
	},
	format: func(t *Type, v any) (string, bool) { a, ok := v.(AccessData); return a.String(), ok },
}

// ---- DPT 27: combined on/off information ----

var onOffInfoCodec = codec{
	encode: func(t *Type, v any) ([]byte, error) {
		o, ok := v.(OnOffInfo)
		if !ok {
			return nil, errValue("%v (%T) is not a dpt.OnOffInfo", v, v)
		}
		return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(nil, o.Valid), o.On), nil
	},
	decode: func(t *Type, b []byte) (any, error) {
		return OnOffInfo{Valid: binary.BigEndian.Uint16(b), On: binary.BigEndian.Uint16(b[2:])}, nil
	},
	parse: func(t *Type, s string) (any, error) {
		// "valid,on" (0x..., 0b... or decimal), or Format's "valid=V on=O".
		if f := strings.Fields(s); len(f) == 2 && strings.HasPrefix(f[0], "valid=") && strings.HasPrefix(f[1], "on=") {
			s = f[0][len("valid="):] + "," + f[1][len("on="):]
		}
		parts := strings.Split(s, ",")
		if len(parts) != 2 {
			return nil, errValue("%q: want valid,on (16-bit masks)", s)
		}
		var m [2]uint16
		for i, p := range parts {
			n, err := strconv.ParseUint(strings.TrimSpace(p), 0, 16)
			if err != nil {
				return nil, errValue("%q: want valid,on (16-bit masks)", s)
			}
			m[i] = uint16(n)
		}
		return OnOffInfo{Valid: m[0], On: m[1]}, nil
	},
	format: func(t *Type, v any) (string, bool) { o, ok := v.(OnOffInfo); return o.String(), ok },
}

// ---- DPT 217: version ----

var versionCodec = codec{
	encode: func(t *Type, v any) ([]byte, error) {
		x, ok := v.(Version)
		if !ok {
			return nil, errValue("%v (%T) is not a dpt.Version", v, v)
		}
		if x.Magic > 31 || x.Version > 31 || x.Revision > 63 {
			return nil, errValue("version %v out of range (magic 0..31, version 0..31, revision 0..63)", x)
		}
		u := uint16(x.Magic)<<11 | uint16(x.Version)<<6 | uint16(x.Revision)
		return binary.BigEndian.AppendUint16(nil, u), nil
	},
	decode: func(t *Type, b []byte) (any, error) {
		u := binary.BigEndian.Uint16(b)
		return Version{Magic: uint8(u >> 11), Version: uint8(u>>6) & 0x1F, Revision: uint8(u) & 0x3F}, nil
	},
	parse: func(t *Type, s string) (any, error) {
		parts := strings.Split(s, ".")
		if len(parts) != 3 {
			return nil, errValue("%q: want magic.version.revision", s)
		}
		var n [3]uint8
		for i, bits := range [3]int{5, 5, 6} {
			x, err := strconv.ParseUint(parts[i], 10, bits)
			if err != nil {
				return nil, errValue("%q: want magic.version.revision (0..31, 0..31, 0..63)", s)
			}
			n[i] = uint8(x)
		}
		return Version{Magic: n[0], Version: n[1], Revision: n[2]}, nil
	},
	format: func(t *Type, v any) (string, bool) { x, ok := v.(Version); return x.String(), ok },
}

// ---- DPT 222, 275: room temperature setpoints ----

// setpointsCodec encodes n (3 or 4) 2-octet floats: comfort, standby,
// economy and, for n = 4, building protection. Each is checked against the
// range of the type.
func setpointsCodec(n int) codec {
	names := [...]string{"comfort", "standby", "economy", "protection"}
	fields := func(r *RoomSetpoints) []*float64 {
		return []*float64{&r.Comfort, &r.Standby, &r.Economy, &r.Protection}[:n]
	}
	return codec{
		encode: func(t *Type, v any) ([]byte, error) {
			r, ok := v.(RoomSetpoints)
			if !ok {
				return nil, errValue("%v (%T) is not a dpt.RoomSetpoints", v, v)
			}
			if n == 3 && r.Protection != 0 {
				return nil, errValue("%s has no building protection setpoint", t.ID)
			}
			out := make([]byte, 0, 2*n)
			for i, f := range fields(&r) {
				raw, err := encodeFloat16In(t, *f)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", names[i], err)
				}
				out = binary.BigEndian.AppendUint16(out, raw)
			}
			return out, nil
		},
		decode: func(t *Type, b []byte) (any, error) {
			var r RoomSetpoints
			for i, f := range fields(&r) {
				x, err := DecodeFloat16(binary.BigEndian.Uint16(b[2*i:]))
				if err != nil {
					return nil, fmt.Errorf("%s: %w", names[i], err)
				}
				*f = x
			}
			return r, nil
		},
		parse: func(t *Type, s string) (any, error) {
			// "21,19,17[,7]", or Format's "comfort=21 standby=19 ...".
			var parts []string
			if strings.Contains(s, "=") {
				for i, w := range strings.Fields(s) {
					if i >= n || !strings.HasPrefix(w, names[i]+"=") {
						return nil, errValue("%q: want %s", s, strings.Join(names[:n], ","))
					}
					parts = append(parts, w[len(names[i])+1:])
				}
			} else {
				parts = strings.Split(s, ",")
			}
			if len(parts) != n {
				return nil, errValue("%q: want %s", s, strings.Join(names[:n], ","))
			}
			var r RoomSetpoints
			for i, f := range fields(&r) {
				x, err := strconv.ParseFloat(strings.TrimSpace(parts[i]), 64)
				if err != nil {
					return nil, errValue("%q: want %s", s, strings.Join(names[:n], ","))
				}
				*f = x
			}
			return r, nil
		},
		format: func(t *Type, v any) (string, bool) {
			r, ok := v.(RoomSetpoints)
			if !ok {
				return "", false
			}
			var sb strings.Builder
			for i, f := range fields(&r) {
				fmt.Fprintf(&sb, "%s=%s ", names[i], strconv.FormatFloat(*f, 'f', -1, 64))
			}
			sb.WriteString(t.Unit)
			return strings.TrimSpace(sb.String()), true
		},
	}
}

// ---- DPT 234: two-letter codes ----

func isLetter(c byte) bool { return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }

var alpha2Codec = codec{
	encode: func(t *Type, v any) ([]byte, error) {
		s, ok := v.(string)
		if !ok {
			return nil, errValue("%v (%T) is not a string", v, v)
		}
		if len(s) != 2 || !isLetter(s[0]) || !isLetter(s[1]) {
			return nil, errValue("%q is not a two-letter code", s)
		}
		return []byte(s), nil
	},
	decode: func(t *Type, b []byte) (any, error) {
		if !isLetter(b[0]) || !isLetter(b[1]) {
			return nil, errValue("% X is not a two-letter code", b)
		}
		return string(b), nil
	},
	parse:  func(t *Type, s string) (any, error) { return unquoteText(s), nil },
	format: func(t *Type, v any) (string, bool) { s, ok := v.(string); return strconv.Quote(s), ok },
}
