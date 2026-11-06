// SPDX-License-Identifier: MIT

package server

import (
	"slices"
	"testing"
)

// DescribeProperty answers the property descriptions of the server's
// interface objects, by PID or (PID 0) by index.
func TestDescribeProperty(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	p := s.props
	objs := p.objects()
	ip := uint8(slices.Index(objs, objKNXnetIP))

	d, ok := p.DescribeProperty(ip, pidFriendlyName, 0)
	if !ok || d.PID != pidFriendlyName || !d.Writable || d.MaxElements != 30 || d.Access != 0xF0 {
		t.Fatalf("friendly name: %+v %v", d, ok)
	}
	// By index: the index of the description names the same property.
	byIdx, ok := p.DescribeProperty(ip, 0, d.Index)
	if !ok || byIdx != d {
		t.Fatalf("by index %d: %+v %v, want %+v", d.Index, byIdx, ok, d)
	}
	// Index 0 is the lowest PID.
	first, ok := p.DescribeProperty(0, 0, 0)
	if !ok || first.Index != 0 || first.PID != pidObjectType || first.Writable {
		t.Fatalf("device object index 0: %+v %v", first, ok)
	}
	for _, c := range []struct {
		name               string
		object, pid, index uint8
	}{
		{"unknown object", uint8(len(objs)), pidObjectType, 0},
		{"index past the properties", 0, 0, 255},
		{"unknown property", 0, 200, 0},
	} {
		if d, ok := p.DescribeProperty(c.object, c.pid, c.index); ok {
			t.Errorf("%s: %+v", c.name, d)
		}
	}
}

// The datatype of every property described has the element size of the
// property.
func TestDescribedTypeSizes(t *testing.T) {
	s, err := New(WithToolKey([16]byte{1}))
	if err != nil {
		t.Fatal(err)
	}
	p := s.props
	n := 0
	for i, obj := range p.objects() {
		for pid, pr := range p.properties(obj) {
			d, ok := p.DescribeProperty(uint8(i), pid, 0)
			if !ok {
				t.Fatalf("object %d PID %d not described", i, pid)
			}
			if size, ok := d.Type.Size(); !ok || size != pr.size {
				t.Errorf("object %d PID %d: %s of %d octets (%v), elements of %d", i, pid, d.Type, size, ok, pr.size)
			}
			n++
		}
	}
	if n == 0 {
		t.Fatal("no properties")
	}
}

// Element 0 of a property is its current element count.
func TestReadElementCount(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	b, code := s.props.readData(objDevice, pidSerialNumber, 0, 1)
	if code != 0 || len(b) != 2 || b[0] != 0 || b[1] != 1 {
		t.Fatalf("count = % X, code %d", b, code)
	}
	if _, code := s.props.readData(objDevice, pidSerialNumber, 0, 2); code != errIndexRange {
		t.Fatalf("count 2 of element 0: code %d", code)
	}
}
