// SPDX-License-Identifier: MIT

package dpt

import "strconv"

// Values of the composite types encoded by a layout (codecs_layout.go).
// Each String returns the text that Type.Format prints and Type.Parse
// reads, for example "height=50.2 slats=100.0 height-valid".

// StatusMode is a DPT 6.020 value: five status bits and the active one of
// three modes.
type StatusMode struct {
	// A to E are the status bits (true: the bit is set).
	A, B, C, D, E bool
	// Mode is the active mode, 0..2 (sent as 001, 010 or 100).
	Mode uint8
}

// String returns "a c mode=1", the set status bits and the mode.
func (s StatusMode) String() string { return formatFields(statusModeFields, &s) }

var statusModeFields = []field[StatusMode]{
	flagField("a", func(s *StatusMode) *bool { return &s.A }),
	flagField("b", func(s *StatusMode) *bool { return &s.B }),
	flagField("c", func(s *StatusMode) *bool { return &s.C }),
	flagField("d", func(s *StatusMode) *bool { return &s.D }),
	flagField("e", func(s *StatusMode) *bool { return &s.E }),
	{
		name: "mode", bits: 3,
		get: func(t *Type, s *StatusMode) (uint64, error) {
			if s.Mode > 2 {
				return 0, errValue("mode %d out of range 0..2", s.Mode)
			}
			return 1 << s.Mode, nil
		},
		set: func(t *Type, s *StatusMode, raw uint64) error {
			switch raw {
			case 1:
				s.Mode = 0
			case 2:
				s.Mode = 1
			case 4:
				s.Mode = 2
			default:
				return errValue("mode bits %03b: want one of 001, 010, 100", raw)
			}
			return nil
		},
		text: func(s *StatusMode) string { return strconv.Itoa(int(s.Mode)) },
		parse: func(t *Type, s *StatusMode, x string) error {
			if len(x) != 1 || x[0] < '0' || x[0] > '2' {
				return errValue("mode=%q: want 0..2", x)
			}
			s.Mode = x[0] - '0'
			return nil
		},
	},
}

// DoubleNibble is a DPT 25 value: two 4-bit numbers. For 25.1000 they are
// the busy and NAK repetitions, 0..3 each.
type DoubleNibble struct {
	Busy, Nak uint8
}

// String returns "busy=1 nak=3".
func (d DoubleNibble) String() string { return formatFields(nibbleFields(15), &d) }

func nibbleFields(max uint64) []field[DoubleNibble] {
	return []field[DoubleNibble]{
		unsignedField("busy", 4, max, func(d *DoubleNibble) *uint8 { return &d.Busy }),
		unsignedField("nak", 4, max, func(d *DoubleNibble) *uint8 { return &d.Nak }),
	}
}

// ModeNext is a DPT 206 value: a mode and the delay before it applies.
type ModeNext struct {
	// Delay is the time until the mode applies, in minutes.
	Delay uint16
	// Mode has the values and names of the subtype (206.100 HVAC mode,
	// 206.102 DHW mode, 206.104 occupancy mode, 206.105 building mode).
	Mode Enum
}

// String returns `delay=30 mode=economy`.
func (m ModeNext) String() string { return formatFields(modeNextFields, &m) }

var modeNextFields = []field[ModeNext]{
	unsignedField("delay", 16, 0, func(m *ModeNext) *uint16 { return &m.Delay }),
	enumField("mode", func(m *ModeNext) *Enum { return &m.Mode }),
}

// AlarmInfo is a DPT 219.001 value: the description of an alarm.
type AlarmInfo struct {
	LogNumber uint8
	// Priority, ApplicationArea and ErrorClass are numbers with the
	// meanings of 20.004, 20.006 and 20.011.
	Priority, ApplicationArea, ErrorClass uint8
	// The alarm supports an error code, an alarm text, a time stamp and
	// an acknowledgement.
	ErrorCodeSupported, AlarmTextSupported, TimestampSupported, AckSupported bool
	Locked, Unacknowledged, InAlarm                                          bool
}

// String returns "log=1 priority=0 area=20 error-class=3 ack-sup in-alarm"
// with the flags that are set.
func (a AlarmInfo) String() string { return formatFields(alarmInfoFields, &a) }

var alarmInfoFields = []field[AlarmInfo]{
	unsignedField("log", 8, 0, func(a *AlarmInfo) *uint8 { return &a.LogNumber }),
	unsignedField("priority", 8, 0, func(a *AlarmInfo) *uint8 { return &a.Priority }),
	unsignedField("area", 8, 0, func(a *AlarmInfo) *uint8 { return &a.ApplicationArea }),
	unsignedField("error-class", 8, 0, func(a *AlarmInfo) *uint8 { return &a.ErrorClass }),
	reserved[AlarmInfo](4),
	flagField("error-code-sup", func(a *AlarmInfo) *bool { return &a.ErrorCodeSupported }),
	flagField("alarm-text-sup", func(a *AlarmInfo) *bool { return &a.AlarmTextSupported }),
	flagField("timestamp-sup", func(a *AlarmInfo) *bool { return &a.TimestampSupported }),
	flagField("ack-sup", func(a *AlarmInfo) *bool { return &a.AckSupported }),
	reserved[AlarmInfo](5),
	flagField("locked", func(a *AlarmInfo) *bool { return &a.Locked }),
	flagField("unacknowledged", func(a *AlarmInfo) *bool { return &a.Unacknowledged }),
	flagField("in-alarm", func(a *AlarmInfo) *bool { return &a.InAlarm }),
}

// ScalingSpeed is a DPT 225 value: a time period and a percentage. 225.001
// (scaling speed) sends the period in steps of 100 ms, 225.002 (scaling
// step time) in steps of 1 ms.
type ScalingSpeed struct {
	// Period is in milliseconds.
	Period uint32
	// Percent is 0..100 % in 255 steps.
	Percent float64
}

// String returns "period=2000 percent=50.2".
func (s ScalingSpeed) String() string { return formatFields(scalingFields(1), &s) }

func scalingFields(scale uint32) []field[ScalingSpeed] {
	return []field[ScalingSpeed]{
		scaledField("period", 16, scale, func(s *ScalingSpeed) *uint32 { return &s.Period }),
		ratioField("percent", 100, func(s *ScalingSpeed) *float64 { return &s.Percent }),
	}
}

// MeteringValue is a DPT 229.001 value: a counter, the code of its unit
// and resolution (value information), and the status of the datapoint.
type MeteringValue struct {
	Count int32
	// ValueInfo is the code of the unit and resolution of Count, for
	// example 3 for energy in Wh or 19 for volume in l.
	ValueInfo uint8
	// The status bits, as DPT 21.001.
	Unacknowledged, InAlarm, Overridden, Fault, OutOfService bool
}

// String returns "count=1234 value-info=3" followed by the set status
// bits.
func (m MeteringValue) String() string { return formatFields(meteringFields, &m) }

var meteringFields = []field[MeteringValue]{
	signedField("count", func(m *MeteringValue) *int32 { return &m.Count }),
	unsignedField("value-info", 8, 0, func(m *MeteringValue) *uint8 { return &m.ValueInfo }),
	reserved[MeteringValue](3),
	flagField("unacknowledged", func(m *MeteringValue) *bool { return &m.Unacknowledged }),
	flagField("in-alarm", func(m *MeteringValue) *bool { return &m.InAlarm }),
	flagField("overridden", func(m *MeteringValue) *bool { return &m.Overridden }),
	flagField("fault", func(m *MeteringValue) *bool { return &m.Fault }),
	flagField("out-of-service", func(m *MeteringValue) *bool { return &m.OutOfService }),
}

// MBusAddress is a DPT 230.1000 value: the address of an M-Bus meter.
type MBusAddress struct {
	Manufacturer uint16
	IdentNumber  uint32
	Version      uint8
	// Medium is the device type code, for example 2 for an electricity
	// meter or 7 for a water meter.
	Medium uint8
}

// String returns "manufacturer=1234 ident=56789 version=1 medium=7".
func (m MBusAddress) String() string { return formatFields(mbusFields, &m) }

var mbusFields = []field[MBusAddress]{
	unsignedField("manufacturer", 16, 0, func(m *MBusAddress) *uint16 { return &m.Manufacturer }),
	unsignedField("ident", 32, 0, func(m *MBusAddress) *uint32 { return &m.IdentNumber }),
	unsignedField("version", 8, 0, func(m *MBusAddress) *uint8 { return &m.Version }),
	unsignedField("medium", 8, 0, func(m *MBusAddress) *uint8 { return &m.Medium }),
}

// HSV is a DPT 232.601 colour: hue 0..360° and saturation and value
// 0..100 %, each in 255 steps.
type HSV struct {
	H, S, V float64
}

// String returns "h=120.0 s=50.2 v=100.0".
func (c HSV) String() string { return formatFields(hsvFields, &c) }

var hsvFields = []field[HSV]{
	ratioField("h", 360, func(c *HSV) *float64 { return &c.H }),
	ratioField("s", 100, func(c *HSV) *float64 { return &c.S }),
	ratioField("v", 100, func(c *HSV) *float64 { return &c.V }),
}

// TariffEnergy is a DPT 235.001 value: active energy in Wh with its
// tariff, each with an invalid flag.
type TariffEnergy struct {
	Energy int32
	Tariff uint8
	// EnergyInvalid and TariffInvalid are set when the field is not
	// valid.
	EnergyInvalid, TariffInvalid bool
}

// String returns "energy=1500 tariff=2" followed by the set flags.
func (e TariffEnergy) String() string { return formatFields(tariffFields, &e) }

var tariffFields = []field[TariffEnergy]{
	signedField("energy", func(e *TariffEnergy) *int32 { return &e.Energy }),
	unsignedField("tariff", 8, 0, func(e *TariffEnergy) *uint8 { return &e.Tariff }),
	reserved[TariffEnergy](6),
	flagField("energy-invalid", func(e *TariffEnergy) *bool { return &e.EnergyInvalid }),
	flagField("tariff-invalid", func(e *TariffEnergy) *bool { return &e.TariffInvalid }),
}

// PriorityControl is a DPT 236.001 value: a mode level with a priority
// level, or the deactivation of that priority.
type PriorityControl struct {
	// Deactivate set ends the priority; clear activates it.
	Deactivate bool
	Priority   uint8 // 0..7
	Mode       uint8 // 0..15
}

// String returns "priority=2 mode=5", preceded by "deactivate" when set.
func (p PriorityControl) String() string { return formatFields(priorityFields, &p) }

var priorityFields = []field[PriorityControl]{
	flagField("deactivate", func(p *PriorityControl) *bool { return &p.Deactivate }),
	unsignedField("priority", 3, 0, func(p *PriorityControl) *uint8 { return &p.Priority }),
	unsignedField("mode", 4, 0, func(p *PriorityControl) *uint8 { return &p.Mode }),
}

// DALIGearDiagnostic is a DPT 237.600 value: the failures of a DALI
// control gear and its address.
type DALIGearDiagnostic struct {
	ConverterError, BallastFailure, LampFailure bool
	// Read set: a read request; clear: a response or a spontaneous
	// message.
	Read bool
	// Group set: Address is a DALI group address; clear: a device
	// address.
	Group   bool
	Address uint8 // 0..63
}

// String returns "lamp-failure group address=3" with the flags that are
// set.
func (d DALIGearDiagnostic) String() string { return formatFields(daliGearFields, &d) }

var daliGearFields = []field[DALIGearDiagnostic]{
	reserved[DALIGearDiagnostic](5),
	flagField("converter-error", func(d *DALIGearDiagnostic) *bool { return &d.ConverterError }),
	flagField("ballast-failure", func(d *DALIGearDiagnostic) *bool { return &d.BallastFailure }),
	flagField("lamp-failure", func(d *DALIGearDiagnostic) *bool { return &d.LampFailure }),
	flagField("read", func(d *DALIGearDiagnostic) *bool { return &d.Read }),
	flagField("group", func(d *DALIGearDiagnostic) *bool { return &d.Group }),
	unsignedField("address", 6, 0, func(d *DALIGearDiagnostic) *uint8 { return &d.Address }),
}

// DALIDiagnostic is a DPT 238.600 value: the failures of a DALI device and
// its address.
type DALIDiagnostic struct {
	BallastFailure, LampFailure bool
	Address                     uint8 // 0..63
}

// String returns "ballast-failure address=12" with the flags that are
// set.
func (d DALIDiagnostic) String() string { return formatFields(daliFields, &d) }

var daliFields = []field[DALIDiagnostic]{
	flagField("ballast-failure", func(d *DALIDiagnostic) *bool { return &d.BallastFailure }),
	flagField("lamp-failure", func(d *DALIDiagnostic) *bool { return &d.LampFailure }),
	unsignedField("address", 6, 0, func(d *DALIDiagnostic) *uint8 { return &d.Address }),
}

// CombinedPosition is a DPT 240.800 value: the height and slats positions
// of a blind, 0..100 % in 255 steps, each with a validity flag.
type CombinedPosition struct {
	Height, Slats           float64
	HeightValid, SlatsValid bool
}

// String returns "height=50.2 slats=100.0 height-valid slats-valid".
func (c CombinedPosition) String() string { return formatFields(positionFields, &c) }

var positionFields = []field[CombinedPosition]{
	ratioField("height", 100, func(c *CombinedPosition) *float64 { return &c.Height }),
	ratioField("slats", 100, func(c *CombinedPosition) *float64 { return &c.Slats }),
	reserved[CombinedPosition](6),
	flagField("slats-valid", func(c *CombinedPosition) *bool { return &c.SlatsValid }),
	flagField("height-valid", func(c *CombinedPosition) *bool { return &c.HeightValid }),
}

// ConverterStatus is a DPT 244.600 value: the state of a DALI emergency
// converter.
type ConverterStatus struct {
	// Mode is the converter mode, 0..15 (for example 1 normal, 4 rest,
	// 5 emergency).
	Mode uint8
	// HardwiredSwitch and HardwiredInhibit are set when active.
	HardwiredSwitch, HardwiredInhibit bool
	// The pending states of the function, duration and partial duration
	// tests and the failure state, 0..3 (0 unknown, 1 no, 2 yes).
	FunctionTest, DurationTest, PartialDurationTest, Failure uint8
}

// String returns "mode=1 function-test=1 duration-test=2 partial-test=1
// failure=1" with the hardwired flags that are set.
func (c ConverterStatus) String() string { return formatFields(converterStatusFields, &c) }

var converterStatusFields = []field[ConverterStatus]{
	unsignedField("mode", 4, 0, func(c *ConverterStatus) *uint8 { return &c.Mode }),
	reserved[ConverterStatus](2),
	flagField("hardwired-switch", func(c *ConverterStatus) *bool { return &c.HardwiredSwitch }),
	flagField("hardwired-inhibit", func(c *ConverterStatus) *bool { return &c.HardwiredInhibit }),
	unsignedField("function-test", 2, 0, func(c *ConverterStatus) *uint8 { return &c.FunctionTest }),
	unsignedField("duration-test", 2, 0, func(c *ConverterStatus) *uint8 { return &c.DurationTest }),
	unsignedField("partial-test", 2, 0, func(c *ConverterStatus) *uint8 { return &c.PartialDurationTest }),
	unsignedField("failure", 2, 0, func(c *ConverterStatus) *uint8 { return &c.Failure }),
}

// ConverterTestResult is a DPT 245.600 value: the results of the last
// tests of a DALI emergency converter.
type ConverterTestResult struct {
	// The results of the function, duration and partial duration tests,
	// 0..15 (for example 1 passed in time, 3 failed).
	FunctionTestResult, DurationTestResult, PartialTestResult uint8
	// How each test was started, 0..3 (1 automatically, 2 by the
	// gateway).
	FunctionTestStart, DurationTestStart, PartialTestStart uint8
	// LDTR is the result of the last duration test, 0..510; LPDTR that
	// of the last partial duration test.
	LDTR  uint16
	LPDTR uint8
}

// String returns "function-result=1 duration-result=1 partial-result=0
// function-start=1 duration-start=2 partial-start=0 ldtr=180 lpdtr=200".
func (c ConverterTestResult) String() string { return formatFields(converterTestFields, &c) }

var converterTestFields = []field[ConverterTestResult]{
	unsignedField("function-result", 4, 0, func(c *ConverterTestResult) *uint8 { return &c.FunctionTestResult }),
	unsignedField("duration-result", 4, 0, func(c *ConverterTestResult) *uint8 { return &c.DurationTestResult }),
	unsignedField("partial-result", 4, 0, func(c *ConverterTestResult) *uint8 { return &c.PartialTestResult }),
	reserved[ConverterTestResult](4),
	unsignedField("function-start", 2, 0, func(c *ConverterTestResult) *uint8 { return &c.FunctionTestStart }),
	unsignedField("duration-start", 2, 0, func(c *ConverterTestResult) *uint8 { return &c.DurationTestStart }),
	unsignedField("partial-start", 2, 0, func(c *ConverterTestResult) *uint8 { return &c.PartialTestStart }),
	reserved[ConverterTestResult](2),
	unsignedField("ldtr", 16, 510, func(c *ConverterTestResult) *uint16 { return &c.LDTR }),
	unsignedField("lpdtr", 8, 0, func(c *ConverterTestResult) *uint8 { return &c.LPDTR }),
}

// ColourTransition is a DPT 249.600 value: a transition to a colour
// temperature and a brightness, each field with a validity flag.
type ColourTransition struct {
	// Period is the transition time in milliseconds, in steps of 100 ms.
	Period uint32
	// Temperature is the absolute colour temperature in K.
	Temperature uint16
	// Brightness is 0..100 % in 255 steps.
	Brightness                                     float64
	PeriodValid, TemperatureValid, BrightnessValid bool
}

// String returns "period=1000 temperature=2700 brightness=50.2" followed
// by the validity flags that are set.
func (c ColourTransition) String() string { return formatFields(transitionFields, &c) }

var transitionFields = []field[ColourTransition]{
	scaledField("period", 16, 100, func(c *ColourTransition) *uint32 { return &c.Period }),
	unsignedField("temperature", 16, 0, func(c *ColourTransition) *uint16 { return &c.Temperature }),
	ratioField("brightness", 100, func(c *ColourTransition) *float64 { return &c.Brightness }),
	reserved[ColourTransition](5),
	flagField("period-valid", func(c *ColourTransition) *bool { return &c.PeriodValid }),
	flagField("temperature-valid", func(c *ColourTransition) *bool { return &c.TemperatureValid }),
	flagField("brightness-valid", func(c *ColourTransition) *bool { return &c.BrightnessValid }),
}

// ColourTemperatureControl is a DPT 250.600 value: a relative step of the
// colour temperature and one of the brightness (each a direction and a
// step code, as DPT 3), each with a validity flag.
type ColourTemperatureControl struct {
	Temperature, Brightness           Step
	TemperatureValid, BrightnessValid bool
}

// String returns "temperature=+3 brightness=stop temperature-valid".
func (c ColourTemperatureControl) String() string { return formatFields(temperatureControlFields, &c) }

var temperatureControlFields = []field[ColourTemperatureControl]{
	reserved[ColourTemperatureControl](4),
	stepField("temperature", func(c *ColourTemperatureControl) *Step { return &c.Temperature }),
	reserved[ColourTemperatureControl](4),
	stepField("brightness", func(c *ColourTemperatureControl) *Step { return &c.Brightness }),
	reserved[ColourTemperatureControl](6),
	flagField("temperature-valid", func(c *ColourTemperatureControl) *bool { return &c.TemperatureValid }),
	flagField("brightness-valid", func(c *ColourTemperatureControl) *bool { return &c.BrightnessValid }),
}

// GeoLocation is a DPT 255.001 value: longitude and latitude in degrees,
// each a 4-octet float.
type GeoLocation struct {
	Longitude, Latitude float64
}

// String returns "longitude=4.35 latitude=50.85".
func (g GeoLocation) String() string { return formatFields(geoFields, &g) }

var geoFields = []field[GeoLocation]{
	float32Field("longitude", func(g *GeoLocation) *float64 { return &g.Longitude }),
	float32Field("latitude", func(g *GeoLocation) *float64 { return &g.Latitude }),
}

// The layouts below follow the KNX master data of schema 23 (version
// 326), most significant field first, as xknx 4.1.1 does. The master data
// of schema 20 lists their fields in the reverse order.

// LightingActuatorStatus is a DPT 207.600 value: the status flags of a
// lighting actuator and its actual value, 0..100 % in 255 steps.
type LightingActuatorStatus struct {
	// ActualValueValid is set when ActualValue is valid.
	ActualValueValid, Locked, Forced, NightMode, Staircase, Dimming, LocalOverride, Failure bool
	ActualValue                                                                             float64
}

// String returns "actual=50.2 dimming actual-valid" with the flags that
// are set.
func (s LightingActuatorStatus) String() string { return formatFields(lightingStatusFields, &s) }

var lightingStatusFields = []field[LightingActuatorStatus]{
	ratioField("actual", 100, func(s *LightingActuatorStatus) *float64 { return &s.ActualValue }),
	flagField("failure", func(s *LightingActuatorStatus) *bool { return &s.Failure }),
	flagField("local-override", func(s *LightingActuatorStatus) *bool { return &s.LocalOverride }),
	flagField("dimming", func(s *LightingActuatorStatus) *bool { return &s.Dimming }),
	flagField("staircase", func(s *LightingActuatorStatus) *bool { return &s.Staircase }),
	flagField("night-mode", func(s *LightingActuatorStatus) *bool { return &s.NightMode }),
	flagField("forced", func(s *LightingActuatorStatus) *bool { return &s.Forced }),
	flagField("locked", func(s *LightingActuatorStatus) *bool { return &s.Locked }),
	flagField("actual-valid", func(s *LightingActuatorStatus) *bool { return &s.ActualValueValid }),
}

// BlindsStatus is a DPT 241.800 value: the status of a sunblind or
// shutter actuator, with the height and slats positions (0..100 % in 255
// steps) and their validity.
type BlindsStatus struct {
	Height, Slats float64
	// UpperEnd and LowerEnd: an end position is reached; LowerPredefined:
	// the lower predefined position is reached.
	UpperEnd, LowerEnd, LowerPredefined bool
	// TargetReached is set when the drive reached its target position,
	// clear while it moves.
	TargetReached bool
	// HeightRestricted and SlatsRestricted: the target position cannot be
	// reached.
	HeightRestricted, SlatsRestricted bool
	// WeatherAlarm: a wind, rain or frost alarm input is in alarm.
	WeatherAlarm, Forced, Locked, LocalOverride, Failure bool
	HeightValid, SlatsValid                              bool
}

// String returns "height=100.0 slats=50.2 slats-valid height-valid
// target-reached lower-end" with the flags that are set.
func (b BlindsStatus) String() string { return formatFields(blindsStatusFields, &b) }

var blindsStatusFields = []field[BlindsStatus]{
	ratioField("height", 100, func(b *BlindsStatus) *float64 { return &b.Height }),
	ratioField("slats", 100, func(b *BlindsStatus) *float64 { return &b.Slats }),
	flagField("slats-valid", func(b *BlindsStatus) *bool { return &b.SlatsValid }),
	flagField("height-valid", func(b *BlindsStatus) *bool { return &b.HeightValid }),
	reserved[BlindsStatus](3),
	flagField("failure", func(b *BlindsStatus) *bool { return &b.Failure }),
	flagField("local-override", func(b *BlindsStatus) *bool { return &b.LocalOverride }),
	flagField("locked", func(b *BlindsStatus) *bool { return &b.Locked }),
	flagField("forced", func(b *BlindsStatus) *bool { return &b.Forced }),
	flagField("weather-alarm", func(b *BlindsStatus) *bool { return &b.WeatherAlarm }),
	flagField("slats-restricted", func(b *BlindsStatus) *bool { return &b.SlatsRestricted }),
	flagField("height-restricted", func(b *BlindsStatus) *bool { return &b.HeightRestricted }),
	flagField("target-reached", func(b *BlindsStatus) *bool { return &b.TargetReached }),
	flagField("lower-predefined", func(b *BlindsStatus) *bool { return &b.LowerPredefined }),
	flagField("lower-end", func(b *BlindsStatus) *bool { return &b.LowerEnd }),
	flagField("upper-end", func(b *BlindsStatus) *bool { return &b.UpperEnd }),
}

// BatteryInfo is a DPT 246.600 value: battery failures and the charge
// level in % (0..255, unscaled).
type BatteryInfo struct {
	BatteryFailure, DurationFailure, FullyCharged bool
	ChargeLevel                                   uint8
}

// String returns "fully-charged charge=100" with the flags that are set.
func (b BatteryInfo) String() string { return formatFields(batteryFields, &b) }

var batteryFields = []field[BatteryInfo]{
	reserved[BatteryInfo](5),
	flagField("fully-charged", func(b *BatteryInfo) *bool { return &b.FullyCharged }),
	flagField("duration-failure", func(b *BatteryInfo) *bool { return &b.DurationFailure }),
	flagField("battery-failure", func(b *BatteryInfo) *bool { return &b.BatteryFailure }),
	unsignedField("charge", 8, 0, func(b *BatteryInfo) *uint8 { return &b.ChargeLevel }),
}

// RelativeRGBW is a DPT 252.600 value: a relative step (DPT 3) of each
// of red, green, blue and white, each with a validity flag. On the wire
// red comes first, then green, blue, white and the validity octet.
type RelativeRGBW struct {
	R, G, B, W                     Step
	ValidR, ValidG, ValidB, ValidW bool
}

// String returns "r=-1 g=stop b=stop w=+3 valid-r valid-w" with the
// validity flags that are set.
func (c RelativeRGBW) String() string { return formatFields(relativeRGBWFields, &c) }

var relativeRGBWFields = []field[RelativeRGBW]{
	reserved[RelativeRGBW](4),
	stepField("r", func(c *RelativeRGBW) *Step { return &c.R }),
	reserved[RelativeRGBW](4),
	stepField("g", func(c *RelativeRGBW) *Step { return &c.G }),
	reserved[RelativeRGBW](4),
	stepField("b", func(c *RelativeRGBW) *Step { return &c.B }),
	reserved[RelativeRGBW](4),
	stepField("w", func(c *RelativeRGBW) *Step { return &c.W }),
	reserved[RelativeRGBW](4),
	flagField("valid-r", func(c *RelativeRGBW) *bool { return &c.ValidR }),
	flagField("valid-g", func(c *RelativeRGBW) *bool { return &c.ValidG }),
	flagField("valid-b", func(c *RelativeRGBW) *bool { return &c.ValidB }),
	flagField("valid-w", func(c *RelativeRGBW) *bool { return &c.ValidW }),
}

// RelativeRGB is a DPT 254.600 value: a relative step (DPT 3) of each of
// red, green and blue, in this order on the wire.
type RelativeRGB struct {
	R, G, B Step
}

// String returns "r=-7 g=stop b=+1".
func (c RelativeRGB) String() string { return formatFields(relativeRGBFields, &c) }

var relativeRGBFields = []field[RelativeRGB]{
	reserved[RelativeRGB](4),
	stepField("r", func(c *RelativeRGB) *Step { return &c.R }),
	reserved[RelativeRGB](4),
	stepField("g", func(c *RelativeRGB) *Step { return &c.G }),
	reserved[RelativeRGB](4),
	stepField("b", func(c *RelativeRGB) *Step { return &c.B }),
}
