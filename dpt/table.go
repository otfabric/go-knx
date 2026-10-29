// SPDX-License-Identifier: MIT

package dpt

// The registry. Names, units and ranges follow KNX Standard volume 3/7/2
// (Datapoint Types); only subtypes with published semantics are listed.

func init() {
	// Main types: the format of the family without application semantics.
	for _, m := range []*Type{
		{ID: ID{1, 0}, Name: "DPT_1", Description: "1-bit boolean", Bits: 1, Kind: KindBool, codec: boolCodec},
		{ID: ID{2, 0}, Name: "DPT_2", Description: "1-bit boolean with control", Bits: 2, Kind: KindControl, codec: controlCodec},
		{ID: ID{3, 0}, Name: "DPT_3", Description: "3-bit controlled", Bits: 4, Kind: KindStep, codec: stepCodec},
		{ID: ID{4, 0}, Name: "DPT_4", Description: "character (ISO 8859-1)", Bits: 8, Kind: KindChar, codec: charCodec},
		{ID: ID{5, 0}, Name: "DPT_5", Description: "8-bit unsigned value", Bits: 8, Kind: KindUnsigned, codec: intCodec(1, false, 1)},
		{ID: ID{6, 0}, Name: "DPT_6", Description: "8-bit signed value", Bits: 8, Kind: KindSigned, codec: intCodec(1, true, 1)},
		{ID: ID{7, 0}, Name: "DPT_7", Description: "2-octet unsigned value", Bits: 16, Kind: KindUnsigned, codec: intCodec(2, false, 1)},
		{ID: ID{8, 0}, Name: "DPT_8", Description: "2-octet signed value", Bits: 16, Kind: KindSigned, codec: intCodec(2, true, 1)},
		{ID: ID{9, 0}, Name: "DPT_9", Description: "2-octet float value", Bits: 16, Kind: KindFloat, Min: Float16Min, Max: Float16Max, HasRange: true, codec: float16Codec},
		{ID: ID{10, 0}, Name: "DPT_10", Description: "time of day", Bits: 24, Kind: KindTime, codec: timeCodec},
		{ID: ID{11, 0}, Name: "DPT_11", Description: "date", Bits: 24, Kind: KindDate, codec: dateCodec},
		{ID: ID{12, 0}, Name: "DPT_12", Description: "4-octet unsigned value", Bits: 32, Kind: KindUnsigned, codec: intCodec(4, false, 1)},
		{ID: ID{13, 0}, Name: "DPT_13", Description: "4-octet signed value", Bits: 32, Kind: KindSigned, codec: intCodec(4, true, 1)},
		{ID: ID{14, 0}, Name: "DPT_14", Description: "4-octet float value (IEEE 754)", Bits: 32, Kind: KindFloat, codec: float32Codec},
		{ID: ID{16, 0}, Name: "DPT_String_ASCII", Description: "character string, 14 ASCII octets", Bits: 112, Kind: KindString, codec: stringCodec},
		{ID: ID{17, 0}, Name: "DPT_17", Description: "scene number", Bits: 8, Kind: KindScene, codec: sceneCodec},
		{ID: ID{18, 0}, Name: "DPT_18", Description: "scene control", Bits: 8, Kind: KindSceneControl, codec: sceneControlCodec},
		{ID: ID{19, 0}, Name: "DPT_19", Description: "date and time", Bits: 64, Kind: KindDateTime, codec: dateTimeCodec},
		{ID: ID{20, 0}, Name: "DPT_20", Description: "1-octet enumeration", Bits: 8, Kind: KindEnum, codec: enumCodec},
		{ID: ID{21, 0}, Name: "DPT_21", Description: "8-bit set", Bits: 8, Kind: KindBits, codec: bitsCodec(1)},
		{ID: ID{22, 0}, Name: "DPT_22", Description: "16-bit set", Bits: 16, Kind: KindBits, codec: bitsCodec(2)},
		{ID: ID{26, 0}, Name: "DPT_26", Description: "scene information", Bits: 8, Kind: KindScene, codec: sceneCodec},
		{ID: ID{29, 0}, Name: "DPT_29", Description: "8-octet signed value", Bits: 64, Kind: KindSigned, codec: intCodec(8, true, 1)},
		{ID: ID{232, 0}, Name: "DPT_232", Description: "3 × 8-bit colour", Bits: 24, Kind: KindRGB, codec: rgbCodec},
		{ID: ID{242, 0}, Name: "DPT_242", Description: "colour xyY", Bits: 48, Kind: KindXYY, codec: xyyCodec},
		{ID: ID{251, 0}, Name: "DPT_251", Description: "colour RGBW", Bits: 48, Kind: KindRGBW, codec: rgbwCodec},
	} {
		mains[m.ID.Main] = m
	}

	// DPT 1.
	for _, b := range []struct {
		sub        uint16
		name, desc string
		f, t       string
	}{
		{1, "DPT_Switch", "switch", "off", "on"},
		{2, "DPT_Bool", "boolean", "false", "true"},
		{3, "DPT_Enable", "enable", "disable", "enable"},
		{4, "DPT_Ramp", "ramp", "no ramp", "ramp"},
		{5, "DPT_Alarm", "alarm", "no alarm", "alarm"},
		{6, "DPT_BinaryValue", "binary value", "low", "high"},
		{7, "DPT_Step", "step", "decrease", "increase"},
		{8, "DPT_UpDown", "up/down", "up", "down"},
		{9, "DPT_OpenClose", "open/close", "open", "close"},
		{10, "DPT_Start", "start/stop", "stop", "start"},
		{11, "DPT_State", "state", "inactive", "active"},
		{12, "DPT_Invert", "invert", "not inverted", "inverted"},
		{13, "DPT_DimSendStyle", "dim send style", "start/stop", "cyclically"},
		{14, "DPT_InputSource", "input source", "fixed", "calculated"},
		{15, "DPT_Reset", "reset", "no action", "reset"},
		{16, "DPT_Ack", "acknowledge", "no action", "acknowledge"},
		{17, "DPT_Trigger", "trigger", "trigger", "trigger"},
		{18, "DPT_Occupancy", "occupancy", "not occupied", "occupied"},
		{19, "DPT_Window_Door", "window/door", "closed", "open"},
		{21, "DPT_LogicalFunction", "logical function", "OR", "AND"},
		{22, "DPT_Scene_AB", "scene A/B", "scene A", "scene B"},
		{23, "DPT_ShutterBlinds_Mode", "shutter/blinds mode", "only move up/down", "move up/down + step-stop"},
		{24, "DPT_DayNight", "day/night", "day", "night"},
		{100, "DPT_Heat_Cool", "heating/cooling", "cooling", "heating"},
	} {
		register(&Type{ID: ID{1, b.sub}, Name: b.name, Description: b.desc, Bits: 1, Kind: KindBool, Labels: []string{b.f, b.t}, codec: boolCodec})
	}

	// DPT 2.
	for _, c := range []struct {
		sub        uint16
		name, desc string
	}{
		{1, "DPT_Switch_Control", "switch with control"}, {2, "DPT_Bool_Control", "boolean with control"},
		{3, "DPT_Enable_Control", "enable with control"}, {4, "DPT_Ramp_Control", "ramp with control"},
		{5, "DPT_Alarm_Control", "alarm with control"}, {6, "DPT_BinaryValue_Control", "binary value with control"},
		{7, "DPT_Step_Control", "step with control"}, {8, "DPT_Direction1_Control", "up/down with control"},
		{9, "DPT_Direction2_Control", "open/close with control"}, {10, "DPT_Start_Control", "start/stop with control"},
		{11, "DPT_State_Control", "state with control"}, {12, "DPT_Invert_Control", "invert with control"},
	} {
		register(&Type{ID: ID{2, c.sub}, Name: c.name, Description: c.desc, Bits: 2, Kind: KindControl, codec: controlCodec})
	}

	// DPT 3.
	register(&Type{ID: ID{3, 7}, Name: "DPT_Control_Dimming", Description: "dimming control (increase/decrease, step code)", Bits: 4, Kind: KindStep, codec: stepCodec})
	register(&Type{ID: ID{3, 8}, Name: "DPT_Control_Blinds", Description: "blinds control (down/up, step code)", Bits: 4, Kind: KindStep, codec: stepCodec})

	// DPT 4.
	register(&Type{ID: ID{4, 1}, Name: "DPT_Char_ASCII", Description: "character (ASCII)", Bits: 8, Kind: KindChar, codec: charCodec})
	register(&Type{ID: ID{4, 2}, Name: "DPT_Char_8859_1", Description: "character (ISO 8859-1)", Bits: 8, Kind: KindChar, codec: charCodec})

	// DPT 5.
	register(&Type{ID: ID{5, 1}, Name: "DPT_Scaling", Description: "percentage 0..100 % (255 steps)", Unit: "%", Bits: 8, Kind: KindFloat, Min: 0, Max: 100, HasRange: true, codec: ratioCodec(100)})
	register(&Type{ID: ID{5, 3}, Name: "DPT_Angle", Description: "angle 0..360° (255 steps)", Unit: "°", Bits: 8, Kind: KindFloat, Min: 0, Max: 360, HasRange: true, codec: ratioCodec(360)})
	for _, u := range []struct {
		sub              uint16
		name, desc, unit string
	}{
		{4, "DPT_Percent_U8", "percentage 0..255 %", "%"},
		{5, "DPT_DecimalFactor", "ratio", ""},
		{6, "DPT_Tariff", "tariff 0..254", ""},
		{10, "DPT_Value_1_Ucount", "counter pulses", "pulses"},
	} {
		t := &Type{ID: ID{5, u.sub}, Name: u.name, Description: u.desc, Unit: u.unit, Bits: 8, Kind: KindUnsigned, codec: intCodec(1, false, 1)}
		if u.sub == 6 {
			t.Min, t.Max, t.HasRange = 0, 254, true
		}
		register(t)
	}

	// DPT 6.
	register(&Type{ID: ID{6, 1}, Name: "DPT_Percent_V8", Description: "percentage -128..127 %", Unit: "%", Bits: 8, Kind: KindSigned, codec: intCodec(1, true, 1)})
	register(&Type{ID: ID{6, 10}, Name: "DPT_Value_1_Count", Description: "counter pulses", Unit: "pulses", Bits: 8, Kind: KindSigned, codec: intCodec(1, true, 1)})

	// DPT 7.
	for _, u := range []struct {
		sub              uint16
		name, desc, unit string
		scale            float64
	}{
		{1, "DPT_Value_2_Ucount", "pulses", "pulses", 1},
		{2, "DPT_TimePeriodMsec", "time period", "ms", 1},
		{3, "DPT_TimePeriod10MSec", "time period (10 ms resolution)", "ms", 10},
		{4, "DPT_TimePeriod100MSec", "time period (100 ms resolution)", "ms", 100},
		{5, "DPT_TimePeriodSec", "time period", "s", 1},
		{6, "DPT_TimePeriodMin", "time period", "min", 1},
		{7, "DPT_TimePeriodHrs", "time period", "h", 1},
		{10, "DPT_PropDataType", "property data type", "", 1},
		{11, "DPT_Length_mm", "length", "mm", 1},
		{12, "DPT_UElCurrentmA", "current", "mA", 1},
		{13, "DPT_Brightness", "brightness", "lx", 1},
		{600, "DPT_Absolute_Colour_Temperature", "absolute colour temperature", "K", 1},
	} {
		k := KindUnsigned
		if u.scale != 1 {
			k = KindFloat
		}
		register(&Type{ID: ID{7, u.sub}, Name: u.name, Description: u.desc, Unit: u.unit, Bits: 16, Kind: k, codec: intCodec(2, false, u.scale)})
	}

	// DPT 8.
	for _, s := range []struct {
		sub              uint16
		name, desc, unit string
		scale            float64
	}{
		{1, "DPT_Value_2_Count", "pulses difference", "pulses", 1},
		{2, "DPT_DeltaTimeMsec", "time lag", "ms", 1},
		{3, "DPT_DeltaTime10MSec", "time lag (10 ms resolution)", "ms", 10},
		{4, "DPT_DeltaTime100MSec", "time lag (100 ms resolution)", "ms", 100},
		{5, "DPT_DeltaTimeSec", "time lag", "s", 1},
		{6, "DPT_DeltaTimeMin", "time lag", "min", 1},
		{7, "DPT_DeltaTimeHrs", "time lag", "h", 1},
		{10, "DPT_Percent_V16", "percentage difference (0.01 % resolution)", "%", 0.01},
		{11, "DPT_Rotation_Angle", "rotation angle", "°", 1},
		{12, "DPT_Length_m", "length", "m", 1},
	} {
		k := KindSigned
		if s.scale != 1 {
			k = KindFloat
		}
		register(&Type{ID: ID{8, s.sub}, Name: s.name, Description: s.desc, Unit: s.unit, Bits: 16, Kind: k, codec: intCodec(2, true, s.scale)})
	}

	// DPT 9. The upper limit 670760 of the standard is capped at the largest
	// encodable value.
	const max9 = Float16Max
	for _, f := range []struct {
		sub              uint16
		name, desc, unit string
		min, max         float64
	}{
		{1, "DPT_Value_Temp", "temperature", "°C", -273, max9},
		{2, "DPT_Value_Tempd", "temperature difference", "K", -670760, max9},
		{3, "DPT_Value_Tempa", "kelvin/hour", "K/h", -670760, max9},
		{4, "DPT_Value_Lux", "illuminance", "lx", 0, max9},
		{5, "DPT_Value_Wsp", "wind speed", "m/s", 0, max9},
		{6, "DPT_Value_Pres", "pressure", "Pa", 0, max9},
		{7, "DPT_Value_Humidity", "humidity", "%", 0, max9},
		{8, "DPT_Value_AirQuality", "air quality", "ppm", 0, max9},
		{9, "DPT_Value_AirFlow", "air flow", "m³/h", -670760, max9},
		{10, "DPT_Value_Time1", "time", "s", -670760, max9},
		{11, "DPT_Value_Time2", "time", "ms", -670760, max9},
		{20, "DPT_Value_Volt", "voltage", "mV", -670760, max9},
		{21, "DPT_Value_Curr", "current", "mA", -670760, max9},
		{22, "DPT_PowerDensity", "power density", "W/m²", -670760, max9},
		{23, "DPT_KelvinPerPercent", "kelvin/percent", "K/%", -670760, max9},
		{24, "DPT_Power", "power", "kW", -670760, max9},
		{25, "DPT_Value_Volume_Flow", "volume flow", "l/h", -670760, max9},
		{26, "DPT_Rain_Amount", "rain amount", "l/m²", -671088.64, max9},
		{27, "DPT_Value_Temp_F", "temperature", "°F", -459.6, max9},
		{28, "DPT_Value_Wsp_kmh", "wind speed", "km/h", 0, max9},
		{29, "DPT_Value_Absolute_Humidity", "absolute humidity", "g/m³", 0, max9},
		{30, "DPT_Concentration_ygm3", "concentration", "µg/m³", 0, max9},
	} {
		register(&Type{ID: ID{9, f.sub}, Name: f.name, Description: f.desc, Unit: f.unit, Bits: 16, Kind: KindFloat, Min: f.min, Max: f.max, HasRange: true, codec: float16Codec})
	}

	// DPT 10, 11.
	register(&Type{ID: ID{10, 1}, Name: "DPT_TimeOfDay", Description: "time of day", Bits: 24, Kind: KindTime, codec: timeCodec})
	register(&Type{ID: ID{11, 1}, Name: "DPT_Date", Description: "date", Bits: 24, Kind: KindDate, codec: dateCodec})

	// DPT 12.
	for _, u := range []struct {
		sub              uint16
		name, desc, unit string
	}{
		{1, "DPT_Value_4_Ucount", "counter pulses", "pulses"},
		{100, "DPT_LongTimePeriod_Sec", "time period", "s"},
		{101, "DPT_LongTimePeriod_Min", "time period", "min"},
		{102, "DPT_LongTimePeriod_Hrs", "time period", "h"},
		{1200, "DPT_VolumeLiquid_Litre", "volume of liquid", "l"},
		{1201, "DPT_Volume_m3", "volume", "m³"},
	} {
		register(&Type{ID: ID{12, u.sub}, Name: u.name, Description: u.desc, Unit: u.unit, Bits: 32, Kind: KindUnsigned, codec: intCodec(4, false, 1)})
	}

	// DPT 13.
	for _, s := range []struct {
		sub              uint16
		name, desc, unit string
		scale            float64
	}{
		{1, "DPT_Value_4_Count", "counter pulses", "pulses", 1},
		{2, "DPT_FlowRate_m3/h", "flow rate (0.0001 m³/h resolution)", "m³/h", 0.0001},
		{10, "DPT_ActiveEnergy", "active energy", "Wh", 1},
		{11, "DPT_ApparantEnergy", "apparent energy", "VAh", 1},
		{12, "DPT_ReactiveEnergy", "reactive energy", "VARh", 1},
		{13, "DPT_ActiveEnergy_kWh", "active energy", "kWh", 1},
		{14, "DPT_ApparantEnergy_kVAh", "apparent energy", "kVAh", 1},
		{15, "DPT_ReactiveEnergy_kVARh", "reactive energy", "kVARh", 1},
		{16, "DPT_ActiveEnergy_MWh", "active energy", "MWh", 1},
		{100, "DPT_LongDeltaTimeSec", "time lag", "s", 1},
	} {
		k := KindSigned
		if s.scale != 1 {
			k = KindFloat
		}
		register(&Type{ID: ID{13, s.sub}, Name: s.name, Description: s.desc, Unit: s.unit, Bits: 32, Kind: k, codec: intCodec(4, true, s.scale)})
	}

	// DPT 14.
	for i, q := range [...]struct{ name, desc, unit string }{
		{"DPT_Value_Acceleration", "acceleration", "m/s²"},
		{"DPT_Value_Acceleration_Angular", "angular acceleration", "rad/s²"},
		{"DPT_Value_Activation_Energy", "activation energy", "J/mol"},
		{"DPT_Value_Activity", "radioactive activity", "1/s"},
		{"DPT_Value_Mol", "amount of substance", "mol"},
		{"DPT_Value_Amplitude", "amplitude", ""},
		{"DPT_Value_AngleRad", "angle", "rad"},
		{"DPT_Value_AngleDeg", "angle", "°"},
		{"DPT_Value_Angular_Momentum", "angular momentum", "J s"},
		{"DPT_Value_Angular_Velocity", "angular velocity", "rad/s"},
		{"DPT_Value_Area", "area", "m²"},
		{"DPT_Value_Capacitance", "capacitance", "F"},
		{"DPT_Value_Charge_DensitySurface", "surface charge density", "C/m²"},
		{"DPT_Value_Charge_DensityVolume", "volume charge density", "C/m³"},
		{"DPT_Value_Compressibility", "compressibility", "m²/N"},
		{"DPT_Value_Conductance", "conductance", "S"},
		{"DPT_Value_Electrical_Conductivity", "conductivity", "S/m"},
		{"DPT_Value_Density", "density", "kg/m³"},
		{"DPT_Value_Electric_Charge", "electric charge", "C"},
		{"DPT_Value_Electric_Current", "electric current", "A"},
		{"DPT_Value_Electric_CurrentDensity", "electric current density", "A/m²"},
		{"DPT_Value_Electric_DipoleMoment", "electric dipole moment", "C m"},
		{"DPT_Value_Electric_Displacement", "electric displacement", "C/m²"},
		{"DPT_Value_Electric_FieldStrength", "electric field strength", "V/m"},
		{"DPT_Value_Electric_Flux", "electric flux", "C"},
		{"DPT_Value_Electric_FluxDensity", "electric flux density", "C/m²"},
		{"DPT_Value_Electric_Polarization", "electric polarization", "C/m²"},
		{"DPT_Value_Electric_Potential", "electric potential", "V"},
		{"DPT_Value_Electric_PotentialDifference", "electric potential difference", "V"},
		{"DPT_Value_ElectromagneticMoment", "electromagnetic moment", "A m²"},
		{"DPT_Value_Electromotive_Force", "electromotive force", "V"},
		{"DPT_Value_Energy", "energy", "J"},
		{"DPT_Value_Force", "force", "N"},
		{"DPT_Value_Frequency", "frequency", "Hz"},
		{"DPT_Value_Angular_Frequency", "angular frequency", "rad/s"},
		{"DPT_Value_Heat_Capacity", "heat capacity", "J/K"},
		{"DPT_Value_Heat_FlowRate", "heat flow rate", "W"},
		{"DPT_Value_Heat_Quantity", "heat quantity", "J"},
		{"DPT_Value_Impedance", "impedance", "Ω"},
		{"DPT_Value_Length", "length", "m"},
		{"DPT_Value_Light_Quantity", "light quantity", "J"},
		{"DPT_Value_Luminance", "luminance", "cd/m²"},
		{"DPT_Value_Luminous_Flux", "luminous flux", "lm"},
		{"DPT_Value_Luminous_Intensity", "luminous intensity", "cd"},
		{"DPT_Value_Magnetic_FieldStrength", "magnetic field strength", "A/m"},
		{"DPT_Value_Magnetic_Flux", "magnetic flux", "Wb"},
		{"DPT_Value_Magnetic_FluxDensity", "magnetic flux density", "T"},
		{"DPT_Value_Magnetic_Moment", "magnetic moment", "A m²"},
		{"DPT_Value_Magnetic_Polarization", "magnetic polarization", "T"},
		{"DPT_Value_Magnetization", "magnetization", "A/m"},
		{"DPT_Value_MagnetomotiveForce", "magnetomotive force", "A"},
		{"DPT_Value_Mass", "mass", "kg"},
		{"DPT_Value_MassFlux", "mass flux", "kg/s"},
		{"DPT_Value_Momentum", "momentum", "N/s"},
		{"DPT_Value_Phase_AngleRad", "phase angle", "rad"},
		{"DPT_Value_Phase_AngleDeg", "phase angle", "°"},
		{"DPT_Value_Power", "power", "W"},
		{"DPT_Value_Power_Factor", "power factor", "cos Φ"},
		{"DPT_Value_Pressure", "pressure", "Pa"},
		{"DPT_Value_Reactance", "reactance", "Ω"},
		{"DPT_Value_Resistance", "resistance", "Ω"},
		{"DPT_Value_Resistivity", "resistivity", "Ω m"},
		{"DPT_Value_SelfInductance", "self inductance", "H"},
		{"DPT_Value_SolidAngle", "solid angle", "sr"},
		{"DPT_Value_Sound_Intensity", "sound intensity", "W/m²"},
		{"DPT_Value_Speed", "speed", "m/s"},
		{"DPT_Value_Stress", "stress", "Pa"},
		{"DPT_Value_Surface_Tension", "surface tension", "N/m"},
		{"DPT_Value_Common_Temperature", "temperature", "°C"},
		{"DPT_Value_Absolute_Temperature", "absolute temperature", "K"},
		{"DPT_Value_TemperatureDifference", "temperature difference", "K"},
		{"DPT_Value_Thermal_Capacity", "thermal capacity", "J/K"},
		{"DPT_Value_Thermal_Conductivity", "thermal conductivity", "W/(m K)"},
		{"DPT_Value_ThermoelectricPower", "thermoelectric power", "V/K"},
		{"DPT_Value_Time", "time", "s"},
		{"DPT_Value_Torque", "torque", "N m"},
		{"DPT_Value_Volume", "volume", "m³"},
		{"DPT_Value_Volume_Flux", "volume flux", "m³/s"},
		{"DPT_Value_Weight", "weight", "N"},
		{"DPT_Value_Work", "work", "J"},
		{"DPT_Value_ApparentPower", "apparent power", "VA"},
	} {
		register(&Type{ID: ID{14, uint16(i)}, Name: q.name, Description: q.desc, Unit: q.unit, Bits: 32, Kind: KindFloat, codec: float32Codec})
	}

	// DPT 16.
	register(&Type{ID: ID{16, 0}, Name: "DPT_String_ASCII", Description: "character string, 14 ASCII octets", Bits: 112, Kind: KindString, codec: stringCodec})
	register(&Type{ID: ID{16, 1}, Name: "DPT_String_8859_1", Description: "character string, 14 ISO 8859-1 octets", Bits: 112, Kind: KindString, codec: stringCodec})

	// DPT 17, 18, 19.
	register(&Type{ID: ID{17, 1}, Name: "DPT_SceneNumber", Description: "scene number 0..63", Bits: 8, Kind: KindScene, codec: sceneCodec})
	register(&Type{ID: ID{18, 1}, Name: "DPT_SceneControl", Description: "scene activation or learning", Bits: 8, Kind: KindSceneControl, codec: sceneControlCodec})
	register(&Type{ID: ID{19, 1}, Name: "DPT_DateTime", Description: "date and time", Bits: 64, Kind: KindDateTime, codec: dateTimeCodec})

	// DPT 20.
	for _, e := range []struct {
		sub        uint16
		name, desc string
		values     map[uint8]string
	}{
		{2, "DPT_BuildingMode", "building mode", map[uint8]string{0: "building in use", 1: "building not used", 2: "building protection"}},
		{3, "DPT_OccMode", "occupancy mode", map[uint8]string{0: "occupied", 1: "standby", 2: "not occupied"}},
		{102, "DPT_HVACMode", "HVAC operating mode", map[uint8]string{0: "auto", 1: "comfort", 2: "standby", 3: "economy", 4: "building protection"}},
		{103, "DPT_DHWMode", "domestic hot water mode", map[uint8]string{0: "auto", 1: "legio protect", 2: "normal", 3: "reduced", 4: "off/frost protect"}},
		{105, "DPT_HVACContrMode", "HVAC controller mode", map[uint8]string{
			0: "auto", 1: "heat", 2: "morning warmup", 3: "cool", 4: "night purge", 5: "precool", 6: "off", 7: "test",
			8: "emergency heat", 9: "fan only", 10: "free cool", 11: "ice", 12: "maximum heating mode", 13: "economic heat/cool mode",
			14: "dehumidification", 15: "calibration mode", 16: "emergency cool mode", 17: "emergency steam mode", 20: "NoDem"}},
	} {
		register(&Type{ID: ID{20, e.sub}, Name: e.name, Description: e.desc, Bits: 8, Kind: KindEnum, Enum: e.values, codec: enumCodec})
	}

	// DPT 21, 22: status bit sets (the bits are kept as a number).
	register(&Type{ID: ID{21, 1}, Name: "DPT_StatusGen", Description: "general status (bit set)", Bits: 8, Kind: KindBits, codec: bitsCodec(1)})

	// DPT 26.
	register(&Type{ID: ID{26, 1}, Name: "DPT_SceneInfo", Description: "scene information (bit 6: inactive)", Bits: 8, Kind: KindBits, codec: bitsCodec(1)})

	// DPT 29.
	register(&Type{ID: ID{29, 10}, Name: "DPT_ActiveEnergy_V64", Description: "active energy", Unit: "Wh", Bits: 64, Kind: KindSigned, codec: intCodec(8, true, 1)})
	register(&Type{ID: ID{29, 11}, Name: "DPT_ApparantEnergy_V64", Description: "apparent energy", Unit: "VAh", Bits: 64, Kind: KindSigned, codec: intCodec(8, true, 1)})
	register(&Type{ID: ID{29, 12}, Name: "DPT_ReactiveEnergy_V64", Description: "reactive energy", Unit: "VARh", Bits: 64, Kind: KindSigned, codec: intCodec(8, true, 1)})

	// Colours.
	register(&Type{ID: ID{232, 600}, Name: "DPT_Colour_RGB", Description: "RGB colour", Bits: 24, Kind: KindRGB, codec: rgbCodec})
	register(&Type{ID: ID{242, 600}, Name: "DPT_Colour_xyY", Description: "colour xyY", Bits: 48, Kind: KindXYY, codec: xyyCodec})
	register(&Type{ID: ID{251, 600}, Name: "DPT_Colour_RGBW", Description: "RGBW colour", Bits: 48, Kind: KindRGBW, codec: rgbwCodec})
}
