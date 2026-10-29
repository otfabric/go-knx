// SPDX-License-Identifier: MIT

// Package dpt encodes and decodes KNX datapoint types (DPT): the
// standardised representations of application values in group telegrams.
//
// A datapoint type is identified by a main number (the format: 9 is the
// 2-octet float) and a subtype (the application semantics: 9.001 is a
// temperature in °C, 9.004 an illuminance in lux). [Lookup] returns the
// [Type] of an identifier from the registry; a Type encodes values to the
// octets of an A_GroupValue_Write or _Response ([Type.Encode]), decodes
// them ([Type.Decode]), checks ranges, and formats and parses values as
// text with their unit.
//
// Decoded values have these Go types, by [Kind]:
//
//	KindBool      bool                 DPT 1
//	KindControl   Control              DPT 2
//	KindStep      Step                 DPT 3
//	KindChar      string (one rune)    DPT 4
//	KindUnsigned  uint64               DPT 5 (unscaled), 7, 12
//	KindSigned    int64                DPT 6, 8, 13, 29
//	KindFloat     float64              DPT 9, 14, scaled 5/7/8/13 subtypes
//	KindTime      TimeOfDay            DPT 10
//	KindDate      Date                 DPT 11
//	KindString    string               DPT 16
//	KindScene     uint8                DPT 17
//	KindSceneControl SceneControl      DPT 18
//	KindDateTime  DateTime             DPT 19
//	KindEnum      Enum                 DPT 20
//	KindBits      uint64 (bit set)     DPT 21, 22, 26
//	KindRGB       RGB                  DPT 232
//	KindRGBW      RGBW                 DPT 251
//	KindXYY       XYY                  DPT 242
//
// Encode accepts these types and, where unambiguous, convertible ones (any
// Go integer or float for a number, a name for an enumeration).
//
// Decode accepts every value the format can carry; Encode also enforces
// the range of the subtype (9.001 decodes -300 °C, but refuses to encode
// it). Dates are checked field by field, not against the calendar.
//
// Only subtypes whose semantics are published (KNX Standard volume 3/7/2,
// Datapoint Types) are registered; an unknown subtype of a known main type
// can still be used through [Lookup] of the main type ("9"), which has the
// format of the family and no application semantics.
package dpt

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/otfabric/go-knx"
)

// ID identifies a datapoint type: main number and subtype.
type ID struct {
	Main uint16
	Sub  uint16
}

// String returns "main.sub" with the subtype written with at least three
// digits ("9.001", "12.1200"); a subtype of 0 on a main type that has no
// subtype 0 is still written ("9.000").
func (id ID) String() string { return fmt.Sprintf("%d.%03d", id.Main, id.Sub) }

// ParseID parses "9.001", "9.1", "DPT9.001", "DPT-9-1", "DPST-9-1" (the
// ETS notation) or a main number alone ("9", "DPT-9", main type with
// subtype 0 and HasSub false).
func ParseID(s string) (id ID, hasSub bool, err error) {
	t := strings.TrimSpace(s)
	u := strings.ToUpper(t)
	switch {
	case strings.HasPrefix(u, "DPST-"):
		t = strings.ReplaceAll(t[5:], "-", ".")
	case strings.HasPrefix(u, "DPT-"):
		t = strings.ReplaceAll(t[4:], "-", ".")
	case strings.HasPrefix(u, "DPT"):
		t = t[3:]
	}
	parts := strings.Split(t, ".")
	if len(parts) > 2 || parts[0] == "" {
		return ID{}, false, fmt.Errorf("%w: datapoint type %q: want main.sub (9.001)", knx.ErrInvalidOption, s)
	}
	m, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return ID{}, false, fmt.Errorf("%w: datapoint type %q: want main.sub (9.001)", knx.ErrInvalidOption, s)
	}
	id.Main = uint16(m)
	if len(parts) == 2 {
		sub, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return ID{}, false, fmt.Errorf("%w: datapoint type %q: want main.sub (9.001)", knx.ErrInvalidOption, s)
		}
		id.Sub, hasSub = uint16(sub), true
	}
	return id, hasSub, nil
}

// Kind is the representation of a datapoint type's values.
type Kind int

// Value kinds; see the package documentation for their Go types.
const (
	KindBool Kind = iota
	KindControl
	KindStep
	KindChar
	KindUnsigned
	KindSigned
	KindFloat
	KindTime
	KindDate
	KindString
	KindScene
	KindSceneControl
	KindDateTime
	KindEnum
	KindBits
	KindRGB
	KindRGBW
	KindXYY
)

var kindNames = [...]string{"bool", "control", "step", "char", "unsigned", "signed", "float", "time", "date", "string", "scene", "scene-control", "datetime", "enum", "bits", "rgb", "rgbw", "xyY"}

// String names the kind.
func (k Kind) String() string {
	if int(k) < len(kindNames) {
		return kindNames[k]
	}
	return fmt.Sprintf("Kind(%d)", int(k))
}

// Type is a datapoint type of the registry.
type Type struct {
	ID ID
	// Name is the KNX name, such as "DPT_Value_Temp".
	Name string
	// Description is a short human-readable description.
	Description string
	// Unit is the unit symbol of numeric types ("°C"), empty if none.
	Unit string
	// Bits is the size of the encoded value in bits (1, 2, 4, 8, 16...).
	Bits int
	Kind Kind
	// Min and Max bound numeric values when HasRange is set.
	Min, Max float64
	HasRange bool
	// Labels are the names of the two values of a DPT 1 subtype (false,
	// true), or of the enumeration values of a DPT 20 subtype.
	Labels []string
	// Enum maps the values of an enumeration to their names.
	Enum map[uint8]string

	codec codec
}

// Small reports whether values are sent in the 6 bits of the APCI octet
// (types of at most 6 bits).
func (t *Type) Small() bool { return t.Bits <= 6 }

// Size returns the encoded length in octets (1 for small types).
func (t *Type) Size() int { return (t.Bits + 7) / 8 }

// String returns "9.001 DPT_Value_Temp".
func (t *Type) String() string { return t.ID.String() + " " + t.Name }

// Encode returns the octets of v. For small types it returns one octet
// holding the value in its low bits.
func (t *Type) Encode(v any) ([]byte, error) {
	b, err := t.codec.encode(t, v)
	if err != nil {
		return nil, fmt.Errorf("dpt %s: %w", t.ID, err)
	}
	return b, nil
}

// Decode decodes the octets of a value. For small types data is the one
// octet of the APCI's low 6 bits; for the others it must have exactly
// [Type.Size] octets.
func (t *Type) Decode(data []byte) (any, error) {
	want := t.Size()
	if len(data) != want {
		return nil, fmt.Errorf("%w: dpt %s: %d octets, want %d", knx.ErrInvalidValue, t.ID, len(data), want)
	}
	if t.Small() && data[0]>>t.Bits != 0 {
		return nil, fmt.Errorf("%w: dpt %s: value 0x%02X has more than %d bits", knx.ErrInvalidValue, t.ID, data[0], t.Bits)
	}
	v, err := t.codec.decode(t, data)
	if err != nil {
		return nil, fmt.Errorf("dpt %s: %w", t.ID, err)
	}
	return v, nil
}

// Format returns v as text with its unit, as the CLI prints it: "21.5 °C",
// "on", "12:30:00".
func (t *Type) Format(v any) string {
	if t.codec.format != nil {
		if s, ok := t.codec.format(t, v); ok {
			return s
		}
	}
	s := fmt.Sprint(v)
	if f, ok := v.(float64); ok {
		s = strconv.FormatFloat(f, 'f', -1, 64)
	}
	if t.Unit != "" {
		return s + " " + t.Unit
	}
	return s
}

// Parse parses a value from text (the inverse of Format without the unit;
// a trailing unit is accepted): "21.5", "on", "true", "12:30:00",
// "2026-10-29", "#FF8000".
func (t *Type) Parse(s string) (any, error) {
	s = strings.TrimSpace(s)
	if t.Unit != "" {
		s = strings.TrimSpace(strings.TrimSuffix(s, t.Unit))
	}
	v, err := t.codec.parse(t, s)
	if err != nil {
		return nil, fmt.Errorf("dpt %s: %w", t.ID, err)
	}
	return v, nil
}

type codec struct {
	encode func(t *Type, v any) ([]byte, error)
	decode func(t *Type, b []byte) (any, error)
	parse  func(t *Type, s string) (any, error)
	format func(t *Type, v any) (string, bool)
}

var registry = map[ID]*Type{}

// mains holds the main types: format without application semantics.
var mains = map[uint16]*Type{}

func register(t *Type) {
	if _, dup := registry[t.ID]; dup {
		panic("dpt: duplicate " + t.ID.String())
	}
	registry[t.ID] = t
}

// Lookup returns the type of an identifier: "9.001" a registered subtype,
// "9" the main type. An unregistered subtype of a known main type is not
// found; use the main type for its format.
func Lookup(s string) (*Type, error) {
	id, hasSub, err := ParseID(s)
	if err != nil {
		return nil, err
	}
	if !hasSub {
		if t, ok := mains[id.Main]; ok {
			return t, nil
		}
		return nil, fmt.Errorf("%w: datapoint type %s", knx.ErrUnsupported, s)
	}
	if t, ok := registry[id]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("%w: datapoint type %s", knx.ErrUnsupported, id)
}

// MustLookup is [Lookup] that panics, for constants.
func MustLookup(s string) *Type {
	t, err := Lookup(s)
	if err != nil {
		panic(err)
	}
	return t
}

// Get returns the registered type of id.
func Get(id ID) (*Type, bool) { t, ok := registry[id]; return t, ok }

// All returns every registered subtype, ordered by identifier.
func All() []*Type {
	out := make([]*Type, 0, len(registry))
	for _, t := range registry {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID.Main != out[j].ID.Main {
			return out[i].ID.Main < out[j].ID.Main
		}
		return out[i].ID.Sub < out[j].ID.Sub
	})
	return out
}

// Mains returns the main types, ordered by number.
func Mains() []*Type {
	out := make([]*Type, 0, len(mains))
	for _, t := range mains {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID.Main < out[j].ID.Main })
	return out
}

func errValue(format string, a ...any) error {
	return fmt.Errorf("%w: %s", knx.ErrInvalidValue, fmt.Sprintf(format, a...))
}
