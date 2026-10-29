// SPDX-License-Identifier: MIT

package knx

import (
	"fmt"
	"strconv"
	"strings"
)

// IndividualAddress is the 16-bit address of a KNX device: area (4 bits),
// line (4 bits) and device (8 bits), written "area.line.device", for
// example 1.1.10.
type IndividualAddress uint16

// NewIndividualAddress returns the address area.line.device. area and line
// must be 0..15.
func NewIndividualAddress(area, line, device uint8) (IndividualAddress, error) {
	if area > 15 || line > 15 {
		return 0, fmt.Errorf("%w: individual address %d.%d.%d: area and line are 0..15", ErrInvalidAddress, area, line, device)
	}
	return IndividualAddress(uint16(area)<<12 | uint16(line)<<8 | uint16(device)), nil
}

// ParseIndividualAddress parses "area.line.device" (decimal, no sign, no
// leading zeros, no spaces). The result formats back to s exactly.
func ParseIndividualAddress(s string) (IndividualAddress, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return 0, fmt.Errorf("%w: individual address %q: want area.line.device", ErrInvalidAddress, s)
	}
	area, err1 := parseField(parts[0], 15)
	line, err2 := parseField(parts[1], 15)
	dev, err3 := parseField(parts[2], 255)
	if err1 != nil || err2 != nil || err3 != nil {
		return 0, fmt.Errorf("%w: individual address %q: area and line are 0..15, device 0..255", ErrInvalidAddress, s)
	}
	return IndividualAddress(area<<12 | line<<8 | dev), nil
}

// MustParseIndividualAddress is [ParseIndividualAddress] that panics on
// error, for constants in programs and tests.
func MustParseIndividualAddress(s string) IndividualAddress {
	a, err := ParseIndividualAddress(s)
	if err != nil {
		panic(err)
	}
	return a
}

// Area returns the area (0..15).
func (a IndividualAddress) Area() uint8 { return uint8(a >> 12) }

// Line returns the line (0..15).
func (a IndividualAddress) Line() uint8 { return uint8(a>>8) & 0x0F }

// Device returns the device (0..255).
func (a IndividualAddress) Device() uint8 { return uint8(a) }

// Uint16 returns the address as sent on the wire.
func (a IndividualAddress) Uint16() uint16 { return uint16(a) }

// String returns "area.line.device".
func (a IndividualAddress) String() string {
	return fmt.Sprintf("%d.%d.%d", a.Area(), a.Line(), a.Device())
}

// MarshalText implements encoding.TextMarshaler.
func (a IndividualAddress) MarshalText() ([]byte, error) { return []byte(a.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (a *IndividualAddress) UnmarshalText(b []byte) error {
	v, err := ParseIndividualAddress(string(b))
	if err != nil {
		return err
	}
	*a = v
	return nil
}

// GroupAddress is a 16-bit KNX group address. Its presentation (three
// levels, two levels or free) is a convention of the installation; the
// address on the wire is always the same 16 bits.
type GroupAddress uint16

// GroupAddressFormat selects the presentation of a [GroupAddress].
type GroupAddressFormat int

// Group address presentations.
const (
	// GroupThreeLevel is main/middle/sub: main 0..31 (5 bits), middle 0..7
	// (3 bits), sub 0..255 (8 bits), for example 1/2/3.
	GroupThreeLevel GroupAddressFormat = iota
	// GroupTwoLevel is main/sub: main 0..31 (5 bits), sub 0..2047
	// (11 bits), for example 1/515.
	GroupTwoLevel
	// GroupFree is the address as one decimal number 0..65535.
	GroupFree
)

// String names the format: "3-level", "2-level" or "free".
func (f GroupAddressFormat) String() string {
	switch f {
	case GroupThreeLevel:
		return "3-level"
	case GroupTwoLevel:
		return "2-level"
	case GroupFree:
		return "free"
	default:
		return fmt.Sprintf("GroupAddressFormat(%d)", int(f))
	}
}

// ParseGroupAddressFormat parses "3-level" ("3", "three"), "2-level" ("2",
// "two") or "free".
func ParseGroupAddressFormat(s string) (GroupAddressFormat, error) {
	switch strings.ToLower(s) {
	case "3-level", "3", "three", "three-level":
		return GroupThreeLevel, nil
	case "2-level", "2", "two", "two-level":
		return GroupTwoLevel, nil
	case "free", "1", "1-level":
		return GroupFree, nil
	}
	return 0, fmt.Errorf("%w: group address format %q: want 3-level, 2-level or free", ErrInvalidAddress, s)
}

// NewGroupAddress3 returns main/middle/sub. main must be 0..31, middle
// 0..7.
func NewGroupAddress3(main, middle, sub uint8) (GroupAddress, error) {
	if main > 31 || middle > 7 {
		return 0, fmt.Errorf("%w: group address %d/%d/%d: main is 0..31, middle 0..7", ErrInvalidAddress, main, middle, sub)
	}
	return GroupAddress(uint16(main)<<11 | uint16(middle)<<8 | uint16(sub)), nil
}

// NewGroupAddress2 returns main/sub. main must be 0..31, sub 0..2047.
func NewGroupAddress2(main uint8, sub uint16) (GroupAddress, error) {
	if main > 31 || sub > 2047 {
		return 0, fmt.Errorf("%w: group address %d/%d: main is 0..31, sub 0..2047", ErrInvalidAddress, main, sub)
	}
	return GroupAddress(uint16(main)<<11 | sub), nil
}

// ParseGroupAddress parses a group address in any presentation: three
// parts ("1/2/3") are main/middle/sub, two parts ("1/515") main/sub, one
// part ("2563") the free 16-bit number. Fields are decimal without sign,
// leading zeros or spaces; out-of-range fields are errors.
func ParseGroupAddress(s string) (GroupAddress, error) {
	g, _, err := ParseGroupAddressWithFormat(s)
	return g, err
}

// ParseGroupAddressWithFormat is [ParseGroupAddress] that also returns the
// presentation s was written in, so that g.Format(f) == s.
func ParseGroupAddressWithFormat(s string) (GroupAddress, GroupAddressFormat, error) {
	parts := strings.Split(s, "/")
	bad := func(want string) (GroupAddress, GroupAddressFormat, error) {
		return 0, 0, fmt.Errorf("%w: group address %q: %s", ErrInvalidAddress, s, want)
	}
	switch len(parts) {
	case 3:
		m, e1 := parseField(parts[0], 31)
		mid, e2 := parseField(parts[1], 7)
		sub, e3 := parseField(parts[2], 255)
		if e1 != nil || e2 != nil || e3 != nil {
			return bad("main is 0..31, middle 0..7, sub 0..255")
		}
		return GroupAddress(m<<11 | mid<<8 | sub), GroupThreeLevel, nil
	case 2:
		m, e1 := parseField(parts[0], 31)
		sub, e2 := parseField(parts[1], 2047)
		if e1 != nil || e2 != nil {
			return bad("main is 0..31, sub 0..2047")
		}
		return GroupAddress(m<<11 | sub), GroupTwoLevel, nil
	case 1:
		v, err := parseField(parts[0], 65535)
		if err != nil {
			return bad("want main/middle/sub, main/sub or 0..65535")
		}
		return GroupAddress(v), GroupFree, nil
	}
	return bad("want main/middle/sub, main/sub or 0..65535")
}

// MustParseGroupAddress is [ParseGroupAddress] that panics on error, for
// constants in programs and tests.
func MustParseGroupAddress(s string) GroupAddress {
	g, err := ParseGroupAddress(s)
	if err != nil {
		panic(err)
	}
	return g
}

// Main returns the main group (0..31) of both level presentations.
func (g GroupAddress) Main() uint8 { return uint8(g >> 11) }

// Middle returns the middle group (0..7) of the three-level presentation.
func (g GroupAddress) Middle() uint8 { return uint8(g>>8) & 0x07 }

// Sub returns the sub group of the three-level presentation (0..255).
func (g GroupAddress) Sub() uint8 { return uint8(g) }

// Sub2 returns the sub group of the two-level presentation (0..2047).
func (g GroupAddress) Sub2() uint16 { return uint16(g) & 0x07FF }

// Uint16 returns the address as sent on the wire.
func (g GroupAddress) Uint16() uint16 { return uint16(g) }

// String returns the three-level presentation main/middle/sub.
func (g GroupAddress) String() string { return g.Format(GroupThreeLevel) }

// Format returns the address in presentation f.
func (g GroupAddress) Format(f GroupAddressFormat) string {
	switch f {
	case GroupTwoLevel:
		return fmt.Sprintf("%d/%d", g.Main(), g.Sub2())
	case GroupFree:
		return strconv.Itoa(int(g))
	default:
		return fmt.Sprintf("%d/%d/%d", g.Main(), g.Middle(), g.Sub())
	}
}

// MarshalText implements encoding.TextMarshaler (three levels).
func (g GroupAddress) MarshalText() ([]byte, error) { return []byte(g.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler (any presentation).
func (g *GroupAddress) UnmarshalText(b []byte) error {
	v, err := ParseGroupAddress(string(b))
	if err != nil {
		return err
	}
	*g = v
	return nil
}

// parseField parses a strict decimal field 0..max.
func parseField(s string, max uint32) (uint16, error) {
	if s == "" || len(s) > 5 || (len(s) > 1 && s[0] == '0') {
		return 0, ErrInvalidAddress
	}
	var v uint32
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return 0, ErrInvalidAddress
		}
		v = v*10 + uint32(c-'0')
	}
	if v > max {
		return 0, ErrInvalidAddress
	}
	return uint16(v), nil
}

// Priority is the priority of a telegram (2 bits of the control field).
type Priority uint8

// Priorities, as encoded on the wire.
const (
	PrioritySystem Priority = 0
	PriorityNormal Priority = 1
	PriorityUrgent Priority = 2
	PriorityLow    Priority = 3
)

// String names the priority.
func (p Priority) String() string {
	switch p {
	case PrioritySystem:
		return "system"
	case PriorityNormal:
		return "normal"
	case PriorityUrgent:
		return "urgent"
	case PriorityLow:
		return "low"
	default:
		return fmt.Sprintf("Priority(%d)", uint8(p))
	}
}

// ParsePriority parses "system", "normal", "urgent" or "low".
func ParsePriority(s string) (Priority, error) {
	for p := PrioritySystem; p <= PriorityLow; p++ {
		if strings.EqualFold(s, p.String()) {
			return p, nil
		}
	}
	return 0, fmt.Errorf("%w: priority %q: want system, normal, urgent or low", ErrInvalidOption, s)
}
