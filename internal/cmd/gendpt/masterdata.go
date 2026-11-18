// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// The elements of knx_master.xml that gendpt reads: the datapoint types
// of the master data and the fields of each subtype's format.
type xKNX struct {
	XMLName    xml.Name
	MasterData struct {
		Version string  `xml:"Version,attr"`
		Types   []xType `xml:"DatapointTypes>DatapointType"`
	} `xml:"MasterData"`
}

type xType struct {
	Number    string `xml:"Number,attr"`
	SizeInBit string `xml:"SizeInBit,attr"`
	Subtypes  []xSub `xml:"DatapointSubtypes>DatapointSubtype"`
}

type xSub struct {
	Number string `xml:"Number,attr"`
	Name   string `xml:"Name,attr"`
	Text   string `xml:"Text,attr"`
	Format struct {
		Fields []xField `xml:",any"`
	} `xml:"Format"`
}

type xField struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Values  []struct {
		Value string `xml:"Value,attr"`
		Text  string `xml:"Text,attr"`
	} `xml:"EnumValue"`
}

// namespacePrefix is the namespace of the ETS project schema; the schema
// number follows it.
const namespacePrefix = "http://knx.org/xml/project/"

// The model gendpt writes, mirroring the types of dpt/masterdata.go.
type masterData struct {
	Schema   int
	Version  int
	Subtypes []subtype
}

type subtype struct {
	Main, Sub  uint16
	Name, Text string
	Bits       int
	Fields     []field
}

type field struct {
	Kind         string // the mdKind constant of the dpt package
	Width        int
	Name, Unit   string
	Cleared, Set string
	Min, Max     float64
	HasRange     bool
	Coefficient  float64
	Encoding     string
	Enum         []enumValue
}

type enumValue struct {
	Value uint32
	Text  string
}

var kinds = map[string]string{
	"Bit":             "mdBit",
	"UnsignedInteger": "mdUnsigned",
	"SignedInteger":   "mdSigned",
	"Float":           "mdFloat",
	"Enumeration":     "mdEnum",
	"Reserved":        "mdReserved",
	"String":          "mdString",
}

// knownAttrs are the attributes of a format field that gendpt reads or
// may ignore. An attribute not listed is an error: a new attribute may
// change what a field means, so the generator stops instead of dropping it.
var knownAttrs = map[string]bool{
	"Id": true, "RefId": true, "Name": true, "Width": true, "Unit": true,
	"Cleared": true, "Set": true, "Coefficient": true, "Encoding": true,
	"MinInclusive": true, "MaxInclusive": true, "MinValue": true, "MaxValue": true,
	// Strings of variable length are not handled by any family rule.
	"NullTerminated": true, "VariableLength": true,
}

// parseMasterData reads the datapoint types of knx_master.xml.
func parseMasterData(data []byte) (*masterData, error) {
	var doc xKNX
	if err := xml.NewDecoder(bytes.NewReader(data)).Decode(&doc); err != nil {
		return nil, err
	}
	if doc.XMLName.Local != "KNX" || !strings.HasPrefix(doc.XMLName.Space, namespacePrefix) {
		return nil, fmt.Errorf("root element {%s}%s: want KNX in %s*", doc.XMLName.Space, doc.XMLName.Local, namespacePrefix)
	}
	md := &masterData{}
	var err error
	if md.Schema, err = strconv.Atoi(strings.TrimPrefix(doc.XMLName.Space, namespacePrefix)); err != nil {
		return nil, fmt.Errorf("namespace %s: no schema number", doc.XMLName.Space)
	}
	if md.Version, err = strconv.Atoi(doc.MasterData.Version); err != nil {
		return nil, fmt.Errorf("MasterData Version %q: %w", doc.MasterData.Version, err)
	}
	if len(doc.MasterData.Types) == 0 {
		return nil, errors.New("no datapoint types")
	}
	// Fields by Id, for RefType; a reference may point to a later subtype,
	// so the references are resolved after every field is read.
	byID := map[string]field{}
	type ref struct {
		sub, field int
		id         string
	}
	var refs []ref
	for _, xt := range doc.MasterData.Types {
		main, err := parseUint16(xt.Number)
		if err != nil {
			return nil, fmt.Errorf("datapoint type %q: %w", xt.Number, err)
		}
		bits, err := strconv.Atoi(xt.SizeInBit)
		if err != nil || bits <= 0 {
			return nil, fmt.Errorf("datapoint type %d: SizeInBit %q", main, xt.SizeInBit)
		}
		for _, xs := range xt.Subtypes {
			sub, err := parseUint16(xs.Number)
			if err != nil {
				return nil, fmt.Errorf("datapoint subtype %d.%q: %w", main, xs.Number, err)
			}
			s := subtype{Main: main, Sub: sub, Name: xs.Name, Text: xs.Text, Bits: bits}
			where := fmt.Sprintf("%d.%03d", main, sub)
			for _, xf := range xs.Format.Fields {
				if xf.XMLName.Local == "RefType" {
					id := attr(xf.Attrs, "RefId")
					if id == "" {
						return nil, fmt.Errorf("%s: RefType without RefId", where)
					}
					refs = append(refs, ref{len(md.Subtypes), len(s.Fields), id})
					s.Fields = append(s.Fields, field{})
					continue
				}
				f, err := parseField(xf)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", where, err)
				}
				if id := attr(xf.Attrs, "Id"); id != "" {
					byID[id] = f
				}
				s.Fields = append(s.Fields, f)
			}
			md.Subtypes = append(md.Subtypes, s)
		}
	}
	for _, r := range refs {
		f, ok := byID[r.id]
		if !ok {
			s := md.Subtypes[r.sub]
			return nil, fmt.Errorf("%d.%03d: RefType %s: no such field", s.Main, s.Sub, r.id)
		}
		md.Subtypes[r.sub].Fields[r.field] = f
	}
	sort.Slice(md.Subtypes, func(i, j int) bool {
		a, b := md.Subtypes[i], md.Subtypes[j]
		return a.Main < b.Main || a.Main == b.Main && a.Sub < b.Sub
	})
	for i := 1; i < len(md.Subtypes); i++ {
		if a, b := md.Subtypes[i-1], md.Subtypes[i]; a.Main == b.Main && a.Sub == b.Sub {
			return nil, fmt.Errorf("%d.%03d given twice", a.Main, a.Sub)
		}
	}
	return md, nil
}

func parseField(xf xField) (field, error) {
	kind, ok := kinds[xf.XMLName.Local]
	if !ok {
		return field{}, fmt.Errorf("unknown format element %s", xf.XMLName.Local)
	}
	for _, a := range xf.Attrs {
		if !knownAttrs[a.Name.Local] {
			return field{}, fmt.Errorf("%s: unknown attribute %s", xf.XMLName.Local, a.Name.Local)
		}
	}
	f := field{
		Kind:     kind,
		Width:    1,
		Name:     attr(xf.Attrs, "Name"),
		Unit:     attr(xf.Attrs, "Unit"),
		Cleared:  attr(xf.Attrs, "Cleared"),
		Set:      attr(xf.Attrs, "Set"),
		Encoding: attr(xf.Attrs, "Encoding"),
	}
	if w := attr(xf.Attrs, "Width"); w != "" {
		n, err := strconv.Atoi(w)
		if err != nil || n <= 0 {
			return field{}, fmt.Errorf("%s: Width %q", xf.XMLName.Local, w)
		}
		f.Width = n
	} else if kind != "mdBit" && !(kind == "mdString" && attr(xf.Attrs, "VariableLength") != "") {
		return field{}, fmt.Errorf("%s without Width", xf.XMLName.Local)
	}
	if c := attr(xf.Attrs, "Coefficient"); c != "" {
		v, err := parseFloat(c)
		if err != nil || v <= 0 {
			return field{}, fmt.Errorf("%s: Coefficient %q", xf.XMLName.Local, c)
		}
		f.Coefficient = v
	}
	lo, hi := "MinInclusive", "MaxInclusive"
	if kind == "mdFloat" {
		lo, hi = "MinValue", "MaxValue"
	}
	if a, b := attr(xf.Attrs, lo), attr(xf.Attrs, hi); a != "" && b != "" {
		min, err1 := parseFloat(a)
		max, err2 := parseFloat(b)
		if err1 != nil || err2 != nil || min > max {
			return field{}, fmt.Errorf("%s: range %q..%q", xf.XMLName.Local, a, b)
		}
		f.Min, f.Max, f.HasRange = min, max, true
	}
	if kind == "mdEnum" {
		for _, v := range xf.Values {
			n, err := strconv.ParseUint(v.Value, 10, 32)
			if err != nil {
				return field{}, fmt.Errorf("EnumValue %q: %w", v.Value, err)
			}
			f.Enum = append(f.Enum, enumValue{Value: uint32(n), Text: v.Text})
		}
	}
	return f, nil
}

func attr(attrs []xml.Attr, name string) string {
	for _, a := range attrs {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func parseUint16(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	return uint16(n), err
}

func parseFloat(s string) (float64, error) {
	v, err := strconv.ParseFloat(s, 64)
	if err == nil && (math.IsInf(v, 0) || math.IsNaN(v)) {
		return 0, fmt.Errorf("%q is not finite", s)
	}
	return v, err
}
