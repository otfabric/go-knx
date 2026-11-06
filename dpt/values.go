// SPDX-License-Identifier: MIT

package dpt

import "fmt"

// Control is a DPT 2 value: a control bit and a value bit.
type Control struct {
	// Control set means "priority control".
	Control bool
	Value   bool
}

// Step is a DPT 3 value (dimming, blinds): a direction and a step code.
// StepCode 0 means break (stop); 1..7 divide the range into 2^(StepCode-1)
// intervals.
type Step struct {
	// Increase is the direction bit: increase (3.007) or down (3.008).
	Increase bool
	StepCode uint8
}

// TimeOfDay is a DPT 10 value.
type TimeOfDay struct {
	// Weekday is 0 (no day), 1 (Monday) .. 7 (Sunday).
	Weekday              uint8
	Hour, Minute, Second uint8
}

// String returns "Mon 12:30:05" or "12:30:05".
func (t TimeOfDay) String() string {
	s := fmt.Sprintf("%02d:%02d:%02d", t.Hour, t.Minute, t.Second)
	if t.Weekday > 0 && t.Weekday <= 7 {
		return weekdays[t.Weekday] + " " + s
	}
	return s
}

var weekdays = [...]string{"", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}

// Date is a DPT 11 value; Year is 1990..2089.
type Date struct {
	Year       int
	Month, Day uint8
}

// String returns "2026-10-29".
func (d Date) String() string { return fmt.Sprintf("%04d-%02d-%02d", d.Year, d.Month, d.Day) }

// DateTime is a DPT 19 value with its quality flags.
type DateTime struct {
	Year                 int // 1900..2155
	Month, Day           uint8
	Weekday              uint8 // 0 any day, 1 Monday .. 7 Sunday
	Hour, Minute, Second uint8 // Hour 24 only as 24:00:00

	Fault        bool // F
	WorkingDay   bool // WD
	NoWorkingDay bool // NWD: WD is not valid
	NoYear       bool // NY
	NoDate       bool // ND: month and day of month not valid
	NoWeekday    bool // NDoW
	NoTime       bool // NT
	SummerTime   bool // SUTI
	// ExternalSync is CLQ: the clock is synchronised to an external
	// source.
	ExternalSync bool
	// ReliableSource is SRC: the synchronisation source is reliable.
	ReliableSource bool
}

// String returns "2026-10-29 12:30:05".
func (d DateTime) String() string {
	return fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", d.Year, d.Month, d.Day, d.Hour, d.Minute, d.Second)
}

// SceneControl is a DPT 18 value.
type SceneControl struct {
	// Learn set stores the current state as the scene; clear activates
	// it.
	Learn bool
	// Scene is the scene number 0..63.
	Scene uint8
}

// Enum is a DPT 20 value: the number and, when the type defines it, its
// name.
type Enum struct {
	Value uint8
	Name  string
}

// String returns the name, or the number when there is none.
func (e Enum) String() string {
	if e.Name != "" {
		return e.Name
	}
	return fmt.Sprint(e.Value)
}

// RGB is a DPT 232.600 colour.
type RGB struct{ R, G, B uint8 }

// String returns "#RRGGBB".
func (c RGB) String() string { return fmt.Sprintf("#%02X%02X%02X", c.R, c.G, c.B) }

// RGBW is a DPT 251.600 colour with the validity of each component.
type RGBW struct {
	R, G, B, W                     uint8
	ValidR, ValidG, ValidB, ValidW bool
}

// String returns "#RRGGBBWW".
func (c RGBW) String() string { return fmt.Sprintf("#%02X%02X%02X%02X", c.R, c.G, c.B, c.W) }

// XYY is a DPT 242.600 colour: CIE x and y (0..1 in steps of 1/65535) and
// brightness (0..100 % in 255 steps), with validity bits.
type XYY struct {
	X, Y            float64
	Brightness      float64
	ColorValid      bool
	BrightnessValid bool
}

// AccessData is a DPT 15.000 value: an access identification code of six
// decimal digits (sent as BCD, most significant digit first) with its
// detection flags and an index.
type AccessData struct {
	// Code is the identification number 0..999999.
	Code uint32
	// Error is E: the detection failed.
	Error bool
	// Permission is P: access is granted.
	Permission bool
	// RightToLeft is D, the reading direction of the code: clear left to
	// right, set right to left.
	RightToLeft bool
	// Encrypted is C: the code is encrypted.
	Encrypted bool
	// Index is 0..15.
	Index uint8
}

// String returns "012345 index=3", followed by the names of the set flags
// (error, permission, right-to-left, encrypted).
func (a AccessData) String() string {
	s := fmt.Sprintf("%06d index=%d", a.Code, a.Index)
	for i, set := range [...]bool{a.Error, a.Permission, a.RightToLeft, a.Encrypted} {
		if set {
			s += " " + accessFlags[i]
		}
	}
	return s
}

var accessFlags = [...]string{"error", "permission", "right-to-left", "encrypted"}

// OnOffInfo is a DPT 27.001 value: the on/off state of up to 16 outputs.
// Bit n of each field is output n+1.
type OnOffInfo struct {
	// Valid is the mask: a set bit means the output's On bit is valid.
	Valid uint16
	// On is the state: a set bit means the output is on.
	On uint16
}

// String returns "valid=0x0003 on=0x0001".
func (o OnOffInfo) String() string { return fmt.Sprintf("valid=0x%04X on=0x%04X", o.Valid, o.On) }

// Version is a DPT 217.001 value: a magic number (0..31), a version
// (0..31) and a revision (0..63).
type Version struct {
	Magic, Version, Revision uint8
}

// String returns "magic.version.revision", for example "0.1.2".
func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Magic, v.Version, v.Revision) }

// RoomSetpoints is a DPT 222 (comfort, standby, economy) or DPT 275
// (with building protection) value: room temperature setpoints in °C, or
// setpoint shifts in K, each a 2-octet float. Protection is 0 for DPT 222.
type RoomSetpoints struct {
	Comfort, Standby, Economy, Protection float64
}

// String returns "comfort=21 standby=19 economy=17 protection=7".
func (r RoomSetpoints) String() string {
	return fmt.Sprintf("comfort=%v standby=%v economy=%v protection=%v", r.Comfort, r.Standby, r.Economy, r.Protection)
}
