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
