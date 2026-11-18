// SPDX-License-Identifier: MIT

package dpt

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/otfabric/go-knx"
)

// The vectors below are worked out by hand from the field layouts; they
// are not taken from the specification or another implementation.

// layoutSamples returns round-trip samples of the kinds encoded by a
// layout: the zero value, every field at its largest value, and a mixed
// value. Percentages and angles are 0 or their maximum, which decode
// exactly.
func layoutSamples(t *Type) []any {
	switch t.Kind {
	case KindStatusMode:
		return []any{StatusMode{}, StatusMode{A: true, B: true, C: true, D: true, E: true, Mode: 2}, StatusMode{B: true, Mode: 1}}
	case KindDoubleNibble:
		m := uint8(15)
		if t.ID.Sub == 1000 {
			m = 3
		}
		return []any{DoubleNibble{}, DoubleNibble{Busy: m, Nak: m}, DoubleNibble{Busy: 1, Nak: 2}}
	case KindModeNext:
		if t.Enum == nil {
			return []any{ModeNext{}, ModeNext{Delay: 65535, Mode: Enum{Value: 255}}}
		}
		var v []any
		for k, n := range t.Enum {
			v = append(v, ModeNext{Delay: uint16(k) * 1000, Mode: Enum{Value: k, Name: n}})
		}
		return v
	case KindAlarmInfo:
		return []any{AlarmInfo{}, AlarmInfo{LogNumber: 255, Priority: 255, ApplicationArea: 255, ErrorClass: 255, ErrorCodeSupported: true,
			AlarmTextSupported: true, TimestampSupported: true, AckSupported: true, Locked: true, Unacknowledged: true, InAlarm: true},
			AlarmInfo{LogNumber: 7, Priority: 1, ApplicationArea: 20, ErrorClass: 3, AckSupported: true, InAlarm: true}}
	case KindScalingSpeed:
		step := uint32(1)
		if t.ID.Sub == 1 {
			step = 100
		}
		return []any{ScalingSpeed{}, ScalingSpeed{Period: 65535 * step, Percent: 100}, ScalingSpeed{Period: 20 * step}}
	case KindMeteringValue:
		return []any{MeteringValue{}, MeteringValue{Count: -2147483648, ValueInfo: 255, Unacknowledged: true, InAlarm: true, Overridden: true, Fault: true, OutOfService: true},
			MeteringValue{Count: 2147483647, ValueInfo: 3, Fault: true}}
	case KindMBusAddress:
		return []any{MBusAddress{}, MBusAddress{Manufacturer: 65535, IdentNumber: 4294967295, Version: 255, Medium: 255}, MBusAddress{Manufacturer: 0x2C2D, IdentNumber: 12345678, Version: 1, Medium: 7}}
	case KindHSV:
		return []any{HSV{}, HSV{H: 360, S: 100, V: 100}, HSV{S: 100}}
	case KindTariffEnergy:
		return []any{TariffEnergy{}, TariffEnergy{Energy: -2147483648, Tariff: 255, EnergyInvalid: true, TariffInvalid: true}, TariffEnergy{Energy: 1500, Tariff: 2}}
	case KindPriorityControl:
		return []any{PriorityControl{}, PriorityControl{Deactivate: true, Priority: 7, Mode: 15}, PriorityControl{Priority: 2, Mode: 5}}
	case KindDALIGearDiagnostic:
		return []any{DALIGearDiagnostic{}, DALIGearDiagnostic{ConverterError: true, BallastFailure: true, LampFailure: true, Read: true, Group: true, Address: 63},
			DALIGearDiagnostic{LampFailure: true, Address: 12}}
	case KindDALIDiagnostic:
		return []any{DALIDiagnostic{}, DALIDiagnostic{BallastFailure: true, LampFailure: true, Address: 63}, DALIDiagnostic{LampFailure: true, Address: 5}}
	case KindCombinedPosition:
		return []any{CombinedPosition{}, CombinedPosition{Height: 100, Slats: 100, HeightValid: true, SlatsValid: true}, CombinedPosition{Height: 100, HeightValid: true}}
	case KindConverterStatus:
		return []any{ConverterStatus{}, ConverterStatus{Mode: 15, HardwiredSwitch: true, HardwiredInhibit: true, FunctionTest: 3, DurationTest: 3, PartialDurationTest: 3, Failure: 3},
			ConverterStatus{Mode: 1, FunctionTest: 1, DurationTest: 2, PartialDurationTest: 1, Failure: 1}}
	case KindConverterTestResult:
		return []any{ConverterTestResult{}, ConverterTestResult{FunctionTestResult: 15, DurationTestResult: 15, PartialTestResult: 15,
			FunctionTestStart: 3, DurationTestStart: 3, PartialTestStart: 3, LDTR: 510, LPDTR: 255},
			ConverterTestResult{FunctionTestResult: 1, DurationTestResult: 3, FunctionTestStart: 1, DurationTestStart: 2, LDTR: 180, LPDTR: 200}}
	case KindColourTransition:
		return []any{ColourTransition{}, ColourTransition{Period: 6553500, Temperature: 65535, Brightness: 100, PeriodValid: true, TemperatureValid: true, BrightnessValid: true},
			ColourTransition{Period: 1000, Temperature: 2700, TemperatureValid: true}}
	case KindColourTemperatureControl:
		return []any{ColourTemperatureControl{}, ColourTemperatureControl{Temperature: Step{Increase: true, StepCode: 7}, Brightness: Step{Increase: true, StepCode: 7}, TemperatureValid: true, BrightnessValid: true},
			ColourTemperatureControl{Temperature: Step{StepCode: 3}, TemperatureValid: true}}
	case KindGeoLocation:
		return []any{GeoLocation{}, GeoLocation{Longitude: 4.25, Latitude: 50.5}, GeoLocation{Longitude: -122.5, Latitude: -33.875}}
	case KindLightingActuatorStatus:
		return []any{LightingActuatorStatus{}, LightingActuatorStatus{ActualValueValid: true, Locked: true, Forced: true, NightMode: true, Staircase: true,
			Dimming: true, LocalOverride: true, Failure: true, ActualValue: 100}, LightingActuatorStatus{ActualValueValid: true, Dimming: true}}
	case KindBlindsStatus:
		return []any{BlindsStatus{}, BlindsStatus{Height: 100, Slats: 100, UpperEnd: true, LowerEnd: true, LowerPredefined: true, TargetReached: true,
			HeightRestricted: true, SlatsRestricted: true, WeatherAlarm: true, Forced: true, Locked: true, LocalOverride: true, Failure: true,
			HeightValid: true, SlatsValid: true}, BlindsStatus{Height: 100, TargetReached: true, HeightValid: true}}
	case KindBatteryInfo:
		return []any{BatteryInfo{}, BatteryInfo{BatteryFailure: true, DurationFailure: true, FullyCharged: true, ChargeLevel: 255}, BatteryInfo{FullyCharged: true, ChargeLevel: 100}}
	case KindRelativeRGBW:
		up := Step{Increase: true, StepCode: 7}
		return []any{RelativeRGBW{}, RelativeRGBW{R: up, G: up, B: up, W: up, ValidR: true, ValidG: true, ValidB: true, ValidW: true},
			RelativeRGBW{R: Step{StepCode: 1}, ValidR: true}}
	case KindRelativeRGB:
		up := Step{Increase: true, StepCode: 7}
		return []any{RelativeRGB{}, RelativeRGB{R: up, G: up, B: up}, RelativeRGB{G: Step{StepCode: 2}}}
	default:
		return nil
	}
}

// TestLayoutVectors encodes and decodes one hand-made vector of each
// composite subtype.
func TestLayoutVectors(t *testing.T) {
	for _, c := range []struct {
		id  string
		v   any
		hex string
	}{
		// a, c set; mode 1 is 010.
		{"6.020", StatusMode{A: true, C: true, Mode: 1}, "a2"},
		{"25.1000", DoubleNibble{Busy: 2, Nak: 3}, "23"},
		{"25", DoubleNibble{Busy: 15, Nak: 1}, "f1"},
		// 30 min, economy.
		{"206.100", ModeNext{Delay: 30, Mode: Enum{3, "economy"}}, "001e03"},
		{"206.102", ModeNext{Delay: 256, Mode: Enum{4, "off/frost protect"}}, "010004"},
		{"206.104", ModeNext{Delay: 1, Mode: Enum{2, "not occupied"}}, "000102"},
		{"206.105", ModeNext{Delay: 65535, Mode: Enum{0, "building in use"}}, "ffff00"},
		// Log 1, priority 2, area 20, error class 3; ack and timestamp
		// supported; locked and in alarm.
		{"219.001", AlarmInfo{LogNumber: 1, Priority: 2, ApplicationArea: 20, ErrorClass: 3, AckSupported: true, TimestampSupported: true, Locked: true, InAlarm: true}, "010214030305"},
		{"219.001", AlarmInfo{ErrorCodeSupported: true, AlarmTextSupported: true, Unacknowledged: true}, "000000000c02"},
		// 2 s in steps of 100 ms; 100 %.
		{"225.001", ScalingSpeed{Period: 2000, Percent: 100}, "0014ff"},
		{"225.002", ScalingSpeed{Period: 2000}, "07d000"},
		// -1, energy in Wh (3), fault and out of service.
		{"229.001", MeteringValue{Count: -1, ValueInfo: 3, Fault: true, OutOfService: true}, "ffffffff0303"},
		{"229.001", MeteringValue{Count: 256, Unacknowledged: true, InAlarm: true, Overridden: true}, "00000100001c"},
		{"230.1000", MBusAddress{Manufacturer: 0x1234, IdentNumber: 0x01020304, Version: 5, Medium: 7}, "1234010203040507"},
		{"232.601", HSV{H: 360, S: 0, V: 100}, "ff00ff"},
		// 1000 Wh, tariff 2; the tariff not valid.
		{"235.001", TariffEnergy{Energy: 1000, Tariff: 2, TariffInvalid: true}, "000003e80201"},
		{"235.001", TariffEnergy{Energy: -1, EnergyInvalid: true}, "ffffffff0002"},
		// Deactivate, priority 5 (101), mode 9 (1001).
		{"236.001", PriorityControl{Deactivate: true, Priority: 5, Mode: 9}, "d9"},
		// Converter error and lamp failure; a read of group address 3.
		{"237.600", DALIGearDiagnostic{ConverterError: true, LampFailure: true, Read: true, Group: true, Address: 3}, "05c3"},
		{"237.600", DALIGearDiagnostic{BallastFailure: true, Address: 63}, "023f"},
		{"238.600", DALIDiagnostic{BallastFailure: true, Address: 5}, "85"},
		{"238.600", DALIDiagnostic{LampFailure: true, Address: 63}, "7f"},
		// Height 100 % valid, slats 0 % not valid.
		{"240.800", CombinedPosition{Height: 100, HeightValid: true}, "ff0001"},
		{"240.800", CombinedPosition{Slats: 100, SlatsValid: true}, "00ff02"},
		// Mode 1, hardwired switch; tests 1, 2, 1; failure 0.
		{"244.600", ConverterStatus{Mode: 1, HardwiredSwitch: true, FunctionTest: 1, DurationTest: 2, PartialDurationTest: 1}, "1264"},
		{"244.600", ConverterStatus{Mode: 9, HardwiredInhibit: true, Failure: 2}, "9102"},
		// Results 1, 3, 2; started 1, 2, 0; LDTR 300, LPDTR 128.
		{"245.600", ConverterTestResult{FunctionTestResult: 1, DurationTestResult: 3, PartialTestResult: 2, FunctionTestStart: 1, DurationTestStart: 2, LDTR: 300, LPDTR: 128}, "132060012c80"},
		// 1 s in steps of 100 ms, 2700 K, 100 %; all valid.
		{"249.600", ColourTransition{Period: 1000, Temperature: 2700, Brightness: 100, PeriodValid: true, TemperatureValid: true, BrightnessValid: true}, "000a0a8cff07"},
		{"249.600", ColourTransition{Period: 100, TemperatureValid: true}, "000100000002"},
		// Temperature +3 valid; brightness -1 not valid.
		{"250.600", ColourTemperatureControl{Temperature: Step{Increase: true, StepCode: 3}, Brightness: Step{StepCode: 1}, TemperatureValid: true}, "0b0102"},
		{"250.600", ColourTemperatureControl{Brightness: Step{Increase: true, StepCode: 7}, BrightnessValid: true}, "000f01"},
		// 1.5° and -2.5°.
		{"255.001", GeoLocation{Longitude: 1.5, Latitude: -2.5}, "3fc00000c0200000"},
		// The master data layouts, most significant field first. 207.600:
		// the flags (actual value valid in bit 7 .. failure in bit 0),
		// then the actual value.
		{"207.600", LightingActuatorStatus{ActualValueValid: true, Dimming: true, ActualValue: 100}, "84ff"},
		{"207.600", LightingActuatorStatus{Locked: true, Failure: true}, "4100"},
		// 241.800: height, slats, then upper end in bit 15 .. failure in
		// bit 5, height valid in bit 1, slats valid in bit 0.
		{"241.800", BlindsStatus{Height: 100, LowerEnd: true, TargetReached: true, HeightValid: true}, "ff005002"},
		{"241.800", BlindsStatus{Slats: 100, UpperEnd: true, WeatherAlarm: true, Failure: true, SlatsValid: true}, "00ff8221"},
		// 246.600: battery failure in bit 2, duration failure in bit 1,
		// fully charged in bit 0, then the charge level.
		{"246.600", BatteryInfo{FullyCharged: true, ChargeLevel: 100}, "0164"},
		{"246.600", BatteryInfo{BatteryFailure: true, DurationFailure: true, ChargeLevel: 255}, "06ff"},
		// 252.600: the validity of white (bit 3) .. red (bit 0), then the
		// steps of white, blue, green and red.
		{"252.600", RelativeRGBW{R: Step{Increase: true, StepCode: 3}, W: Step{StepCode: 1}, ValidR: true, ValidW: true}, "090100000b"},
		{"252.600", RelativeRGBW{G: Step{Increase: true, StepCode: 7}, ValidG: true}, "0200000f00"},
		// 254.600: the steps of blue, green and red.
		{"254.600", RelativeRGB{R: Step{Increase: true, StepCode: 1}, G: Step{StepCode: 7}}, "000709"},
		{"254.600", RelativeRGB{B: Step{Increase: true, StepCode: 2}}, "0a0000"},
	} {
		if b := enc(t, c.id, c.v); !bytes.Equal(b, hx(c.hex)) {
			t.Errorf("%s Encode(%+v) = % X, want %s", c.id, c.v, b, c.hex)
		}
		if v := dec(t, c.id, hx(c.hex)); !reflect.DeepEqual(v, c.v) {
			t.Errorf("%s Decode(%s) = %+v, want %+v", c.id, c.hex, v, c.v)
		}
	}
}

func TestLayoutDecodeErrors(t *testing.T) {
	for _, c := range []struct{ id, hex string }{
		{"6.020", "00"}, {"6.020", "03"}, {"6.020", "f8"}, // mode bits not one-hot
		{"25.1000", "40"}, {"25.1000", "04"}, // repetitions above 3
		{"206.100", "000005"}, {"206.104", "000003"}, // not a mode of the subtype
		{"219.001", "000000001000"}, {"219.001", "000000000008"}, // reserved bits
		{"229.001", "000000000020"},
		{"235.001", "000000000004"},
		{"237.600", "0800"},
		{"240.800", "000004"},
		{"244.600", "0400"},
		{"245.600", "000100000000"}, {"245.600", "000001000000"},
		{"245.600", "000001ff0000"}, // LDTR 511
		{"249.600", "000000000008"},
		{"250.600", "100000"}, {"250.600", "001000"}, {"250.600", "000004"},
		{"255.001", "7fc0000000000000"}, {"255.001", "000000007f800000"}, // NaN, +Inf
		{"241.800", "00000004"}, {"246.600", "0800"},
		{"252.600", "1000000000"}, {"252.600", "0010000000"}, {"252.600", "0000000010"},
		{"254.600", "100000"}, {"254.600", "000010"},
		{"6.020", ""}, {"245.600", "0000"}, // length
	} {
		v, err := MustLookup(c.id).Decode(hx(c.hex))
		if v != nil {
			t.Errorf("%s Decode(%s) = %#v", c.id, c.hex, v)
		}
		wantInvalid(t, c.id+" "+c.hex, err)
	}
}

func TestLayoutEncodeErrors(t *testing.T) {
	for _, c := range []struct {
		id string
		v  any
	}{
		{"6.020", StatusMode{Mode: 3}},
		{"6.020", 5},
		{"25.1000", DoubleNibble{Busy: 4}},
		{"25", DoubleNibble{Nak: 16}},
		{"206.100", ModeNext{Mode: Enum{Value: 5}}},
		{"206.100", DoubleNibble{}},
		{"225.001", ScalingSpeed{Period: 150}},     // not a multiple of 100 ms
		{"225.001", ScalingSpeed{Period: 6553600}}, // above 65535 steps
		{"225.002", ScalingSpeed{Period: 65536}},
		{"225.002", ScalingSpeed{Percent: 100.5}},
		{"225.002", ScalingSpeed{Percent: -1}},
		{"232.601", HSV{H: 361}},
		{"236.001", PriorityControl{Priority: 8}},
		{"236.001", PriorityControl{Mode: 16}},
		{"237.600", DALIGearDiagnostic{Address: 64}},
		{"238.600", DALIDiagnostic{Address: 64}},
		{"240.800", CombinedPosition{Height: 101}},
		{"244.600", ConverterStatus{Mode: 16}},
		{"244.600", ConverterStatus{Failure: 4}},
		{"245.600", ConverterTestResult{LDTR: 511}},
		{"245.600", ConverterTestResult{PartialTestStart: 4}},
		{"249.600", ColourTransition{Period: 50}},
		{"250.600", ColourTemperatureControl{Brightness: Step{StepCode: 8}}},
		{"255.001", GeoLocation{Longitude: 1e39}},
		{"255.001", GeoLocation{Latitude: math.NaN()}},
		{"207.600", LightingActuatorStatus{ActualValue: 100.5}},
		{"241.800", BlindsStatus{Slats: -1}},
		{"252.600", RelativeRGBW{W: Step{StepCode: 8}}},
		{"254.600", RelativeRGBW{}},
	} {
		b, err := MustLookup(c.id).Encode(c.v)
		if b != nil {
			t.Errorf("%s Encode(%#v) = % X", c.id, c.v, b)
		}
		wantInvalid(t, c.id, err)
	}
}

func TestLayoutText(t *testing.T) {
	for _, c := range []struct {
		id, text string
		v        any
	}{
		{"6.020", "a c mode=1", StatusMode{A: true, C: true, Mode: 1}},
		{"25.1000", "busy=2 nak=3", DoubleNibble{Busy: 2, Nak: 3}},
		{"206.100", `delay=30 mode="building protection"`, ModeNext{Delay: 30, Mode: Enum{4, "building protection"}}},
		{"219.001", "log=1 priority=2 area=20 error-class=3 ack-sup in-alarm", AlarmInfo{LogNumber: 1, Priority: 2, ApplicationArea: 20, ErrorClass: 3, AckSupported: true, InAlarm: true}},
		{"225.001", "period=2000 percent=100.0", ScalingSpeed{Period: 2000, Percent: 100}},
		{"229.001", "count=-5 value-info=19 fault", MeteringValue{Count: -5, ValueInfo: 19, Fault: true}},
		{"230.1000", "manufacturer=4660 ident=16909060 version=5 medium=7", MBusAddress{Manufacturer: 0x1234, IdentNumber: 0x01020304, Version: 5, Medium: 7}},
		{"232.601", "h=360.0 s=0.0 v=100.0", HSV{H: 360, V: 100}},
		{"235.001", "energy=1000 tariff=2 tariff-invalid", TariffEnergy{Energy: 1000, Tariff: 2, TariffInvalid: true}},
		{"236.001", "deactivate priority=5 mode=9", PriorityControl{Deactivate: true, Priority: 5, Mode: 9}},
		{"237.600", "lamp-failure group address=3", DALIGearDiagnostic{LampFailure: true, Group: true, Address: 3}},
		{"238.600", "ballast-failure address=5", DALIDiagnostic{BallastFailure: true, Address: 5}},
		{"240.800", "height=100.0 slats=0.0 height-valid", CombinedPosition{Height: 100, HeightValid: true}},
		{"244.600", "mode=1 hardwired-switch function-test=1 duration-test=2 partial-test=1 failure=0", ConverterStatus{Mode: 1, HardwiredSwitch: true, FunctionTest: 1, DurationTest: 2, PartialDurationTest: 1}},
		{"245.600", "function-result=1 duration-result=0 partial-result=0 function-start=1 duration-start=0 partial-start=0 ldtr=300 lpdtr=128", ConverterTestResult{FunctionTestResult: 1, FunctionTestStart: 1, LDTR: 300, LPDTR: 128}},
		{"249.600", "period=1000 temperature=2700 brightness=0.0 temperature-valid", ColourTransition{Period: 1000, Temperature: 2700, TemperatureValid: true}},
		{"250.600", "temperature=+3 brightness=stop temperature-valid", ColourTemperatureControl{Temperature: Step{Increase: true, StepCode: 3}, TemperatureValid: true}},
		{"255.001", "longitude=1.5 latitude=-2.5", GeoLocation{Longitude: 1.5, Latitude: -2.5}},
		{"207.600", "actual-valid dimming actual=100.0", LightingActuatorStatus{ActualValueValid: true, Dimming: true, ActualValue: 100}},
		{"241.800", "height=100.0 slats=0.0 lower-end target-reached height-valid", BlindsStatus{Height: 100, LowerEnd: true, TargetReached: true, HeightValid: true}},
		{"246.600", "fully-charged charge=100", BatteryInfo{FullyCharged: true, ChargeLevel: 100}},
		{"252.600", "valid-w valid-r w=-1 b=stop g=stop r=+3", RelativeRGBW{R: Step{Increase: true, StepCode: 3}, W: Step{StepCode: 1}, ValidR: true, ValidW: true}},
		{"254.600", "b=stop g=-7 r=+1", RelativeRGB{R: Step{Increase: true, StepCode: 1}, G: Step{StepCode: 7}}},
	} {
		ty := MustLookup(c.id)
		if s := ty.Format(c.v); s != c.text {
			t.Errorf("%s Format = %q, want %q", c.id, s, c.text)
		}
		if s := fmtString(c.v); s != c.text {
			t.Errorf("%s String = %q, want %q", c.id, s, c.text)
		}
		if v, err := ty.Parse(c.text); err != nil || !reflect.DeepEqual(v, c.v) {
			t.Errorf("%s Parse(%q) = %+v, %v", c.id, c.text, v, err)
		}
	}
	// Fields in any order, missing ones zero, flags as name=bool, names
	// and enumeration names in any case.
	for _, c := range []struct {
		id, text string
		v        any
	}{
		{"240.800", "HEIGHT-VALID=true slats=50.2", CombinedPosition{Slats: 50.2, HeightValid: true}},
		{"206.104", "mode=Standby", ModeNext{Mode: Enum{1, "standby"}}},
		{"206.104", "mode=2 delay=0x10", ModeNext{Delay: 16, Mode: Enum{2, "not occupied"}}},
		{"6.020", "e=false b mode=0", StatusMode{B: true}},
		{"236.001", "", PriorityControl{}},
	} {
		if v, err := MustLookup(c.id).Parse(c.text); err != nil || !reflect.DeepEqual(v, c.v) {
			t.Errorf("%s Parse(%q) = %+v, %v", c.id, c.text, v, err)
		}
	}
	for _, c := range []struct{ id, text string }{
		{"240.800", "height"},             // a number without a value
		{"240.800", "width=3"},            // unknown field
		{"240.800", "height=x"},           // not a number
		{"240.800", "height-valid=maybe"}, // not a boolean
		{"206.100", "mode=holiday"},
		{"206.100", `mode="economy`}, // unterminated quote
		{"6.020", "mode=3"},
		{"25.1000", "busy=4"},
		{"225.001", "period=-1"},
		{"229.001", "count=2147483648"},
		{"250.600", "temperature=+9"},
		{"255.001", "latitude=north"},
	} {
		if _, err := MustLookup(c.id).Parse(c.text); !errors.Is(err, knx.ErrInvalidValue) {
			t.Errorf("%s Parse(%q): %v, want ErrInvalidValue", c.id, c.text, err)
		}
	}
}

func TestLayoutKinds(t *testing.T) {
	for k, want := range map[Kind]string{KindStatusMode: "status-mode", KindGeoLocation: "geo-location", KindHSV: "hsv"} {
		if k.String() != want {
			t.Errorf("%d.String() = %q", int(k), k.String())
		}
	}
	for _, id := range []string{"6.020", "25.1000", "236.001", "238.600"} {
		if ty := MustLookup(id); ty.Small() || ty.Size() != 1 {
			t.Errorf("%s: Small %v Size %d", id, ty.Small(), ty.Size())
		}
	}
}

func fmtString(v any) string { return v.(interface{ String() string }).String() }
