// SPDX-License-Identifier: MIT

package dpt

import (
	"bufio"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
)

// notInMasterData are hand-written subtypes that the pinned master data
// does not have, with the reason.
var notInMasterData = map[ID]string{
	{21, 1200}: "3/7/2 v2.2 (virtual dry contact); not in the master data",
	{21, 1201}: "3/7/2 v2.2 (phase status); not in the master data",
	{234, 2}:   "3/7/2 v2.2 (region code); not in the master data",
}

// registryNames are the master data names of the subtypes whose
// hand-written name differs other than in case. The registry keeps its
// names: callers look types up by them, and earlier releases use them.
var registryNames = map[ID]string{
	{9, 30}:    "DPT_Concentration_µgm3",
	{12, 1201}: "DPT_Volume_m³",
	{13, 11}:   "DPT_ApparentEnergy",
	{13, 14}:   "DPT_ApparentEnergy_kVAh",
	{13, 1200}: "DPT_DeltaVolumeLiquid_Litre ",
	{13, 1201}: "DPT_DeltaVolume_m³",
	{20, 801}:  "DPT_SABExcept-Behaviour",
	{29, 11}:   "DPT_ApparentEnergy_V64",
	{225, 1}:   "Scaling Speed",
	{225, 2}:   "Scaling step time",
}

func masterByID() map[ID]*mdSubtype {
	m := make(map[ID]*mdSubtype, len(masterSubtypes))
	for i := range masterSubtypes {
		m[masterSubtypes[i].ID] = &masterSubtypes[i]
	}
	return m
}

// The generated constants are those of dpt/masterdata.lock.
func TestMasterDataLock(t *testing.T) {
	f, err := os.Open("masterdata.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	lock := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, _ := strings.Cut(line, " ")
		lock[k] = strings.TrimSpace(v)
	}
	want := map[string]string{
		"url":     masterDataURL,
		"schema":  strconv.Itoa(masterDataSchema),
		"version": strconv.Itoa(masterDataVersion),
		"sha256":  masterDataSHA256,
	}
	for k, v := range want {
		if lock[k] != v {
			t.Errorf("masterdata.lock %s = %q, masterdata_gen.go has %q: run make generate", k, lock[k], v)
		}
	}
	if len(masterSubtypes) == 0 {
		t.Fatal("no master data subtypes")
	}
	for i := 1; i < len(masterSubtypes); i++ {
		a, b := masterSubtypes[i-1].ID, masterSubtypes[i].ID
		if a.Main > b.Main || a.Main == b.Main && a.Sub >= b.Sub {
			t.Errorf("masterSubtypes not sorted: %s before %s", a, b)
		}
	}
}

// Every subtype of the master data is registered or listed, with the
// reason, in masterDataNotRegistered; the list holds nothing stale.
func TestMasterDataCoverage(t *testing.T) {
	md := masterByID()
	for i := range masterSubtypes {
		id := masterSubtypes[i].ID
		_, registered := registry[id]
		_, listed := masterDataNotRegistered[id]
		switch {
		case !registered && !listed:
			t.Errorf("%s %s: in the master data, neither registered nor in masterDataNotRegistered", id, masterSubtypes[i].Name)
		case registered && listed:
			t.Errorf("%s: registered and in masterDataNotRegistered", id)
		}
	}
	for id, why := range masterDataNotRegistered {
		if md[id] == nil {
			t.Errorf("masterDataNotRegistered %s (%s): not in the master data", id, why)
		}
		if why == "" {
			t.Errorf("masterDataNotRegistered %s: no reason", id)
		}
	}
	for _, id := range masterRegistered {
		if registry[id] == nil || md[id] == nil {
			t.Errorf("%s: registered from the master data but missing", id)
		}
	}
}

// The hand-written table agrees with the master data: every subtype is in
// it (or in notInMasterData), with the size of its main type, the same
// name, and enumeration values that the master data defines; a value the
// table leaves out is one the master data marks reserved.
func TestRegistryAgainstMasterData(t *testing.T) {
	md := masterByID()
	for id, r := range registry {
		s := md[id]
		if why, ok := notInMasterData[id]; ok {
			if s != nil {
				t.Errorf("%s is in notInMasterData (%s) but the master data has it", id, why)
			}
			continue
		}
		if s == nil {
			t.Errorf("%s %s: not in the master data", id, r.Name)
			continue
		}
		if s.Bits != r.Bits {
			t.Errorf("%s: %d bits, the master data has %d", id, r.Bits, s.Bits)
		}
		if want, ok := registryNames[id]; ok {
			if s.Name != want {
				t.Errorf("%s: registryNames has %q, the master data now %q", id, want, s.Name)
			}
		} else if !strings.EqualFold(s.Name, r.Name) {
			t.Errorf("%s: name %q, the master data has %q", id, r.Name, s.Name)
		}
		if r.Kind != KindEnum || len(s.Fields) != 1 || s.Fields[0].Kind != mdEnum {
			continue
		}
		defined := map[uint8]string{}
		for _, v := range s.Fields[0].Enum {
			defined[uint8(v.Value)] = v.Text
		}
		for v := range r.Enum {
			if _, ok := defined[v]; !ok {
				t.Errorf("%s: value %d is not in the master data", id, v)
			}
		}
		for v, text := range defined {
			if _, ok := r.Enum[v]; !ok && !mdReservedText(text) {
				t.Errorf("%s: value %d (%q) of the master data is missing", id, v, text)
			}
		}
	}
	for id := range registryNames {
		if registry[id] == nil {
			t.Errorf("registryNames %s: not registered", id)
		}
	}
}

// The subtypes registered from the master data encode and decode.
func TestMasterRegisteredRoundTrip(t *testing.T) {
	if len(masterRegistered) == 0 {
		t.Skip("the hand-written table has every subtype masterType knows")
	}
	for _, id := range masterRegistered {
		typ := registry[id]
		if typ.Name == "" || typ.Description == "" {
			t.Errorf("%s: no name or description", id)
		}
		v, err := typ.Decode(make([]byte, typ.Size()))
		if err != nil {
			// An enumeration whose 0 is reserved: take its first value.
			for k := range typ.Enum {
				v, err = typ.Decode([]byte{k})
				break
			}
		}
		if err != nil {
			t.Fatalf("%s: decode: %v", id, err)
		}
		if _, err := typ.Encode(v); err != nil {
			t.Errorf("%s: encode %v: %v", id, v, err)
		}
	}
}

func TestMasterType(t *testing.T) {
	bit := mdField{Kind: mdBit, Width: 1, Cleared: "Off", Set: "On"}
	enum := func(w int) mdField {
		return mdField{Kind: mdEnum, Width: w, Enum: []mdEnumValue{{0, "Reserved"}, {1, "Comfort"}, {2, ""}, {3, "comfort"}, {300, "wide"}}}
	}
	u := func(w int, c float64) mdField { return mdField{Kind: mdUnsigned, Width: w, Coefficient: c, Unit: "u"} }
	s := func(w int, c float64) mdField { return mdField{Kind: mdSigned, Width: w, Coefficient: c} }
	for _, tc := range []struct {
		main   uint16
		bits   int
		fields []mdField
		kind   Kind
		ok     bool
	}{
		{1, 1, []mdField{bit}, KindBool, true},
		{1, 1, []mdField{u(1, 0)}, 0, false},
		{2, 2, []mdField{bit, bit}, KindControl, true},
		{2, 2, []mdField{bit}, 0, false},
		{3, 4, []mdField{bit, u(3, 0)}, KindStep, true},
		{3, 4, []mdField{bit, u(2, 0)}, 0, false},
		{4, 8, []mdField{{Kind: mdString, Width: 8}}, KindChar, true},
		{4, 8, []mdField{u(8, 0)}, 0, false},
		{16, 112, []mdField{{Kind: mdString, Width: 112}}, KindString, true},
		{16, 112, []mdField{{Kind: mdString, Width: 8}}, 0, false},
		{5, 8, []mdField{u(8, 0)}, KindUnsigned, true},
		{5, 8, []mdField{u(8, 100.0/255)}, KindFloat, true},
		{5, 8, []mdField{u(8, 0.3921566)}, KindFloat, true},
		{5, 8, []mdField{u(8, 0.5)}, 0, false},
		{5, 8, []mdField{u(16, 0)}, 0, false},
		{7, 16, []mdField{u(16, 10)}, KindFloat, true},
		{7, 16, []mdField{{Kind: mdUnsigned, Width: 16, Min: 1, Max: 9, HasRange: true}}, KindUnsigned, true},
		{8, 16, []mdField{s(16, 0.01)}, KindFloat, true},
		{8, 16, []mdField{s(16, 1)}, KindSigned, true},
		{6, 8, []mdField{s(8, 100.0/255)}, 0, false},
		{13, 32, []mdField{bit}, 0, false},
		{9, 16, []mdField{{Kind: mdFloat, Width: 16, Min: -1e9, Max: 10, HasRange: true}}, KindFloat, true},
		{9, 16, []mdField{{Kind: mdFloat, Width: 16}}, KindFloat, true},
		{14, 32, []mdField{{Kind: mdFloat, Width: 32, Unit: "W"}}, KindFloat, true},
		{14, 32, []mdField{{Kind: mdFloat, Width: 16}}, 0, false},
		{20, 8, []mdField{enum(8)}, KindEnum, true},
		{23, 2, []mdField{enum(2)}, KindEnum, true},
		{20, 8, []mdField{enum(2)}, 0, false},
		{21, 8, []mdField{{Kind: mdReserved, Width: 7}, bit}, KindBits, true},
		{22, 16, []mdField{u(16, 0)}, 0, false},
		{30, 24, []mdField{bit}, KindBits, true},
		{232, 24, []mdField{u(24, 0)}, 0, false},
	} {
		sub := &mdSubtype{ID: ID{tc.main, 9999}, Name: "DPT_X", Text: "Some text", Bits: tc.bits, Fields: tc.fields}
		typ, ok := masterType(sub)
		if ok != tc.ok {
			t.Errorf("%d %v: ok %v, want %v", tc.main, tc.fields, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if typ.Kind != tc.kind || typ.Description != "some text" || typ.Bits != tc.bits {
			t.Errorf("%d %v: %v %q %d bits", tc.main, tc.fields, typ.Kind, typ.Description, typ.Bits)
		}
		b, err := typ.Encode(mustDecodeZeroOrFirst(t, typ))
		if err != nil || len(b) != typ.Size() {
			t.Errorf("%d: encode: %x %v", tc.main, b, err)
		}
	}

	ratio, _ := masterType(&mdSubtype{ID: ID{5, 9999}, Bits: 8, Fields: []mdField{u(8, 1.4117647)}})
	if !ratio.HasRange || ratio.Max != 360 {
		t.Errorf("1.4117647: range %v..%v, want 0..360", ratio.Min, ratio.Max)
	}
	f9, _ := masterType(&mdSubtype{ID: ID{9, 9999}, Bits: 16, Fields: []mdField{{Kind: mdFloat, Width: 16, Min: -1e9, Max: 10, HasRange: true}}})
	if f9.Min != Float16Min || f9.Max != 10 {
		t.Errorf("DPT 9 range %v..%v, want %v..10", f9.Min, f9.Max, Float16Min)
	}
	e, _ := masterType(&mdSubtype{ID: ID{20, 9999}, Bits: 8, Fields: []mdField{enum(8)}})
	want := map[uint8]string{1: "comfort", 2: "2", 3: "comfort (3)"}
	if len(e.Enum) != len(want) {
		t.Errorf("enum %v, want %v", e.Enum, want)
	}
	for k, v := range want {
		if e.Enum[k] != v {
			t.Errorf("enum %d = %q, want %q", k, e.Enum[k], v)
		}
	}
	if _, err := e.Encode(uint8(0)); err == nil {
		t.Error("a reserved value encodes")
	}
	b, _ := masterType(&mdSubtype{ID: ID{1, 9999}, Bits: 1, Fields: []mdField{bit}})
	if b.Labels[0] != "off" || b.Labels[1] != "on" {
		t.Errorf("labels %v", b.Labels)
	}
}

func mustDecodeZeroOrFirst(t *testing.T, typ *Type) any {
	t.Helper()
	if v, err := typ.Decode(make([]byte, typ.Size())); err == nil {
		return v
	}
	for k := range typ.Enum {
		v, err := typ.Decode([]byte{k})
		if err == nil {
			return v
		}
	}
	t.Fatalf("%s: no value decodes", typ.ID)
	return nil
}

func TestMasterDataHelpers(t *testing.T) {
	for in, want := range map[string]string{
		"Off": "off", "DALI gear": "DALI gear", "OR": "OR", "": "", "x": "x", "A": "A",
		"  Extract   air ": "extract air", "Éclair": "éclair", "1 s": "1 s",
	} {
		if got := mdText(in); got != want {
			t.Errorf("mdText(%q) = %q, want %q", in, got, want)
		}
	}
	for c, want := range map[float64]float64{0.3921566: 100, 1.4117647: 360, 0.5: 0, 0.001: 0, 1.0 / 255: 1} {
		if got := mdRatio(c); got != want {
			t.Errorf("mdRatio(%v) = %v, want %v", c, got, want)
		}
	}
	for c, want := range map[float64]bool{1: true, 10: true, 0.01: true, 1e-6: true, 1e7: false, 0.5: false, 0: false, -10: false, math.Inf(1): false} {
		if got := mdPowerOfTen(c); got != want {
			t.Errorf("mdPowerOfTen(%v) = %v, want %v", c, got, want)
		}
	}
	for s, want := range map[string]bool{"reserved": true, " Reserved ": true, "reserved, no effect": false} {
		if got := mdReservedText(s); got != want {
			t.Errorf("mdReservedText(%q) = %v", s, got)
		}
	}
}

// layoutBits returns the bit positions where the fields of a layout start
// (the first bit is 0) and the reserved bits.
func layoutBits(widths []int) (starts, reserved map[int]bool) {
	starts, reserved = map[int]bool{}, map[int]bool{}
	pos := 0
	for _, w := range widths {
		starts[pos] = true
		n := w
		if w < 0 {
			n = -w
			for i := pos; i < pos+n; i++ {
				reserved[i] = true
			}
		}
		pos += n
	}
	return starts, reserved
}

// The layouts written by hand split the bits as the master data does:
// a field starts where a field of the master data starts (a layout may
// join fields, as a DPT 3 step joins the direction bit and the step code),
// and the reserved bits are the same.
func TestLayoutsAgainstMasterData(t *testing.T) {
	md := masterByID()
	n := 0
	for id, r := range registry {
		s := md[id]
		if r.codec.layout == nil || s == nil {
			continue
		}
		n++
		var mw []int
		total := 0
		for _, f := range s.Fields {
			w := f.Width
			if f.Kind == mdReserved {
				w = -w
			}
			mw = append(mw, w)
			total += f.Width
		}
		if total != s.Bits {
			t.Errorf("%s: the master data fields have %d bits, the type %d", id, total, s.Bits)
			continue
		}
		gotStarts, gotReserved := layoutBits(r.codec.layout)
		wantStarts, wantReserved := layoutBits(mw)
		for p := range gotStarts {
			if !wantStarts[p] {
				t.Errorf("%s: a field starts at bit %d, none of the master data does (layout %v, master data %v)", id, p, r.codec.layout, mw)
			}
		}
		if len(gotReserved) != len(wantReserved) {
			t.Errorf("%s: %d reserved bits, the master data has %d (layout %v, master data %v)", id, len(gotReserved), len(wantReserved), r.codec.layout, mw)
		}
		for p := range wantReserved {
			if !gotReserved[p] {
				t.Errorf("%s: bit %d is reserved in the master data", id, p)
			}
		}
	}
	if n == 0 {
		t.Fatal("no layout compared")
	}
}
