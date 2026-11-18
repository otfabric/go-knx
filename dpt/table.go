// SPDX-License-Identifier: MIT

package dpt

// The registry. Names, units and ranges follow KNX Standard volume 3/7/2
// (Datapoint Types) and the KNX master data; only subtypes with published
// semantics are listed. The subtypes below are written by hand; the other
// subtypes of the master data whose format is known are registered from
// masterdata_gen.go at the end (registerMasterData).

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
		{ID: ID{15, 0}, Name: "DPT_15", Description: "access data (6 BCD digits, flags, index)", Bits: 32, Kind: KindAccess, codec: accessCodec},
		{ID: ID{16, 0}, Name: "DPT_String_ASCII", Description: "character string, 14 ASCII octets", Bits: 112, Kind: KindString, codec: stringCodec},
		{ID: ID{17, 0}, Name: "DPT_17", Description: "scene number", Bits: 8, Kind: KindScene, codec: sceneCodec},
		{ID: ID{18, 0}, Name: "DPT_18", Description: "scene control", Bits: 8, Kind: KindSceneControl, codec: sceneControlCodec},
		{ID: ID{19, 0}, Name: "DPT_19", Description: "date and time", Bits: 64, Kind: KindDateTime, codec: dateTimeCodec},
		{ID: ID{20, 0}, Name: "DPT_20", Description: "1-octet enumeration", Bits: 8, Kind: KindEnum, codec: enumCodec},
		{ID: ID{21, 0}, Name: "DPT_21", Description: "8-bit set", Bits: 8, Kind: KindBits, codec: bitsCodec(1)},
		{ID: ID{22, 0}, Name: "DPT_22", Description: "16-bit set", Bits: 16, Kind: KindBits, codec: bitsCodec(2)},
		{ID: ID{23, 0}, Name: "DPT_23", Description: "2-bit enumeration", Bits: 2, Kind: KindEnum, codec: enumCodec},
		{ID: ID{25, 0}, Name: "DPT_25", Description: "two 4-bit values", Bits: 8, Kind: KindDoubleNibble, codec: layoutCodec(nibbleFields(15))},
		{ID: ID{26, 0}, Name: "DPT_26", Description: "scene information (bit set)", Bits: 8, Kind: KindBits, codec: bitsCodec(1)},
		{ID: ID{27, 0}, Name: "DPT_27", Description: "combined on/off information (16-bit mask, 16-bit state)", Bits: 32, Kind: KindOnOffInfo, codec: onOffInfoCodec},
		{ID: ID{29, 0}, Name: "DPT_29", Description: "8-octet signed value", Bits: 64, Kind: KindSigned, codec: intCodec(8, true, 1)},
		{ID: ID{30, 0}, Name: "DPT_30", Description: "24-bit set", Bits: 24, Kind: KindBits, codec: bitsCodec(3)},
		{ID: ID{206, 0}, Name: "DPT_206", Description: "time delay (min) and 8-bit mode", Bits: 24, Kind: KindModeNext, codec: modeNextCodec},
		{ID: ID{207, 0}, Name: "DPT_207", Description: "8-bit set and percentage", Bits: 16, Kind: KindLightingActuatorStatus, codec: layoutCodec(lightingStatusFields)},
		{ID: ID{217, 0}, Name: "DPT_217", Description: "version (magic, version, revision)", Bits: 16, Kind: KindVersion, codec: versionCodec},
		{ID: ID{219, 0}, Name: "DPT_219", Description: "alarm information", Bits: 48, Kind: KindAlarmInfo, codec: layoutCodec(alarmInfoFields)},
		{ID: ID{222, 0}, Name: "DPT_222", Description: "3 × 2-octet float", Bits: 48, Kind: KindSetpoints, Min: Float16Min, Max: Float16Max, HasRange: true, codec: setpointsCodec(3)},
		{ID: ID{225, 0}, Name: "DPT_225", Description: "time period (ms) and percentage", Bits: 24, Kind: KindScalingSpeed, codec: layoutCodec(scalingFields(1))},
		{ID: ID{229, 0}, Name: "DPT_229", Description: "metering value (counter, value information, status)", Bits: 48, Kind: KindMeteringValue, codec: layoutCodec(meteringFields)},
		{ID: ID{230, 0}, Name: "DPT_230", Description: "M-Bus address", Bits: 64, Kind: KindMBusAddress, codec: layoutCodec(mbusFields)},
		{ID: ID{232, 0}, Name: "DPT_232", Description: "3 × 8-bit colour", Bits: 24, Kind: KindRGB, codec: rgbCodec},
		{ID: ID{234, 0}, Name: "DPT_234", Description: "two ASCII letters", Bits: 16, Kind: KindString, codec: alpha2Codec},
		{ID: ID{235, 0}, Name: "DPT_235", Description: "active energy and tariff with validity", Bits: 48, Kind: KindTariffEnergy, codec: layoutCodec(tariffFields)},
		{ID: ID{236, 0}, Name: "DPT_236", Description: "prioritised mode control", Bits: 8, Kind: KindPriorityControl, codec: layoutCodec(priorityFields)},
		{ID: ID{237, 0}, Name: "DPT_237", Description: "DALI control gear diagnostic", Bits: 16, Kind: KindDALIGearDiagnostic, codec: layoutCodec(daliGearFields)},
		{ID: ID{238, 0}, Name: "DPT_238", Description: "DALI diagnostic", Bits: 8, Kind: KindDALIDiagnostic, codec: layoutCodec(daliFields)},
		{ID: ID{240, 0}, Name: "DPT_240", Description: "height and slats positions with validity", Bits: 24, Kind: KindCombinedPosition, codec: layoutCodec(positionFields)},
		{ID: ID{241, 0}, Name: "DPT_241", Description: "height and slats positions with status", Bits: 32, Kind: KindBlindsStatus, codec: layoutCodec(blindsStatusFields)},
		{ID: ID{242, 0}, Name: "DPT_242", Description: "colour xyY", Bits: 48, Kind: KindXYY, codec: xyyCodec},
		{ID: ID{244, 0}, Name: "DPT_244", Description: "DALI converter status", Bits: 16, Kind: KindConverterStatus, codec: layoutCodec(converterStatusFields)},
		{ID: ID{245, 0}, Name: "DPT_245", Description: "DALI converter test result", Bits: 48, Kind: KindConverterTestResult, codec: layoutCodec(converterTestFields)},
		{ID: ID{246, 0}, Name: "DPT_246", Description: "battery information", Bits: 16, Kind: KindBatteryInfo, codec: layoutCodec(batteryFields)},
		{ID: ID{249, 0}, Name: "DPT_249", Description: "time period, colour temperature and brightness with validity", Bits: 48, Kind: KindColourTransition, codec: layoutCodec(transitionFields)},
		{ID: ID{250, 0}, Name: "DPT_250", Description: "colour temperature and brightness steps with validity", Bits: 24, Kind: KindColourTemperatureControl, codec: layoutCodec(temperatureControlFields)},
		{ID: ID{251, 0}, Name: "DPT_251", Description: "colour RGBW", Bits: 48, Kind: KindRGBW, codec: rgbwCodec},
		{ID: ID{252, 0}, Name: "DPT_252", Description: "relative RGBW control", Bits: 40, Kind: KindRelativeRGBW, codec: layoutCodec(relativeRGBWFields)},
		{ID: ID{254, 0}, Name: "DPT_254", Description: "relative RGB control", Bits: 24, Kind: KindRelativeRGB, codec: layoutCodec(relativeRGBFields)},
		{ID: ID{255, 0}, Name: "DPT_255", Description: "2 × 4-octet float (longitude, latitude)", Bits: 64, Kind: KindGeoLocation, codec: layoutCodec(geoFields)},
		{ID: ID{275, 0}, Name: "DPT_275", Description: "4 × 2-octet float", Bits: 64, Kind: KindSetpoints, Min: Float16Min, Max: Float16Max, HasRange: true, codec: setpointsCodec(4)},
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
		{100, "DPT_FanStage", "fan stage 0..255", ""},
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
	register(&Type{ID: ID{6, 20}, Name: "DPT_Status_Mode3", Description: "status bits A..E and the active one of modes 0..2", Bits: 8, Kind: KindStatusMode, codec: layoutCodec(statusModeFields)})

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
		{31, "DPT_Coefficient", "coefficient", "", 0, max9},
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
		{1200, "DPT_DeltaVolumeLiquid_Litre", "volume of liquid difference", "l", 1},
		{1201, "DPT_DeltaVolume_m3", "volume difference", "m³", 1},
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
	register(&Type{ID: ID{14, 1200}, Name: "DPT_Volume_Flux_Meter", Description: "volume flux of a meter", Unit: "m³/h", Bits: 32, Kind: KindFloat, codec: float32Codec})
	register(&Type{ID: ID{14, 1201}, Name: "DPT_Volume_Flux_ls", Description: "volume flux of a meter", Unit: "l/s", Bits: 32, Kind: KindFloat, codec: float32Codec})

	// DPT 15.
	register(&Type{ID: ID{15, 0}, Name: "DPT_Access_Data", Description: "access data (6 BCD digits, flags, index)", Bits: 32, Kind: KindAccess, codec: accessCodec})

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
		{1, "DPT_SCLOMode", "SCLO mode", map[uint8]string{0: "autonomous", 1: "slave", 2: "master"}},
		{2, "DPT_BuildingMode", "building mode", map[uint8]string{0: "building in use", 1: "building not used", 2: "building protection"}},
		{3, "DPT_OccMode", "occupancy mode", map[uint8]string{0: "occupied", 1: "standby", 2: "not occupied"}},
		{4, "DPT_Priority", "priority", map[uint8]string{0: "high", 1: "medium", 2: "low", 3: "void"}},
		{5, "DPT_LightApplicationMode", "light application mode", map[uint8]string{0: "normal", 1: "presence simulation", 2: "night round"}},
		{6, "DPT_ApplicationArea", "application area", map[uint8]string{
			0: "no fault", 1: "system and functions of common interest", 10: "HVAC general FBs", 11: "HVAC hot water heating",
			12: "HVAC direct electrical heating", 13: "HVAC terminal units", 14: "HVAC VAC", 20: "lighting", 30: "security",
			40: "load management", 50: "shutters and blinds"}},
		{7, "DPT_AlarmClassType", "alarm class type", map[uint8]string{1: "simple alarm", 2: "basic alarm", 3: "extended alarm"}},
		{8, "DPT_PSUMode", "PSU mode", map[uint8]string{0: "disabled", 1: "enabled", 2: "auto"}},
		{11, "DPT_ErrorClass_System", "system error class", map[uint8]string{
			0: "no fault", 1: "general device fault", 2: "communication fault", 3: "configuration fault", 4: "hardware fault",
			5: "software fault", 6: "insufficient non-volatile memory", 7: "insufficient volatile memory",
			8: "memory allocation command with size 0", 9: "CRC error", 10: "watchdog reset detected", 11: "invalid opcode detected",
			12: "general protection fault", 13: "maximum table length exceeded", 14: "undefined load command",
			15: "group address table not sorted", 16: "invalid connection number", 17: "invalid group object number",
			18: "group object type too long"}},
		{12, "DPT_ErrorClass_HVAC", "HVAC error class", map[uint8]string{0: "no fault", 1: "sensor fault", 2: "process/controller fault", 3: "actuator fault", 4: "other fault"}},
		{13, "DPT_Time_Delay", "time delay", map[uint8]string{
			0: "not active", 1: "1 s", 2: "2 s", 3: "3 s", 4: "5 s", 5: "10 s", 6: "15 s", 7: "20 s", 8: "30 s", 9: "45 s",
			10: "1 min", 11: "1.25 min", 12: "1.5 min", 13: "2 min", 14: "2.5 min", 15: "3 min", 16: "5 min", 17: "15 min",
			18: "20 min", 19: "30 min", 20: "1 h", 21: "2 h", 22: "3 h", 23: "5 h", 24: "12 h", 25: "24 h"}},
		{14, "DPT_Beaufort_Wind_Force_Scale", "wind force (Beaufort scale)", map[uint8]string{
			0: "calm", 1: "light air", 2: "light breeze", 3: "gentle breeze", 4: "moderate breeze", 5: "fresh breeze",
			6: "strong breeze", 7: "near gale", 8: "fresh gale", 9: "strong gale", 10: "storm", 11: "violent storm", 12: "hurricane"}},
		{17, "DPT_SensorSelect", "sensor mode", map[uint8]string{
			0: "inactive", 1: "digital input", 2: "digital input inverted", 3: "analog input", 4: "temperature sensor input"}},
		{20, "DPT_ActuatorConnectType", "actuator connect type", map[uint8]string{1: "sensor connection", 2: "controller connection"}},
		// Cloud cover in oktas; the published list names neither 6 nor 7.
		{21, "DPT_Cloud_Cover", "cloud cover", map[uint8]string{
			0: "cloudless", 1: "sunny", 2: "sunshiny", 3: "lightly cloudy", 4: "scattered clouds", 5: "cloudy",
			6: "6 oktas", 7: "7 oktas", 8: "overcast", 9: "sky obstructed"}},
		{22, "DPT_PowerReturnMode", "power return mode", map[uint8]string{0: "do not send", 1: "send always", 2: "send if changed during power down"}},
		{100, "DPT_FuelType", "fuel type", map[uint8]string{0: "auto", 1: "oil", 2: "gas", 3: "solid state fuel"}},
		{101, "DPT_BurnerType", "burner type", map[uint8]string{1: "1 stage", 2: "2 stage", 3: "modulating"}},
		{102, "DPT_HVACMode", "HVAC operating mode", map[uint8]string{0: "auto", 1: "comfort", 2: "standby", 3: "economy", 4: "building protection"}},
		{103, "DPT_DHWMode", "domestic hot water mode", map[uint8]string{0: "auto", 1: "legio protect", 2: "normal", 3: "reduced", 4: "off/frost protect"}},
		{104, "DPT_LoadPriority", "load priority", map[uint8]string{0: "none", 1: "shift load priority", 2: "absolute load priority"}},
		{105, "DPT_HVACContrMode", "HVAC controller mode", map[uint8]string{
			0: "auto", 1: "heat", 2: "morning warmup", 3: "cool", 4: "night purge", 5: "precool", 6: "off", 7: "test",
			8: "emergency heat", 9: "fan only", 10: "free cool", 11: "ice", 12: "maximum heating mode", 13: "economic heat/cool mode",
			14: "dehumidification", 15: "calibration mode", 16: "emergency cool mode", 17: "emergency steam mode", 20: "NoDem"}},
		{106, "DPT_HVACEmergMode", "HVAC emergency mode", map[uint8]string{
			0: "normal", 1: "emergency pressure", 2: "emergency depressure", 3: "emergency purge", 4: "emergency shutdown", 5: "emergency fire"}},
		{107, "DPT_ChangeoverMode", "changeover mode", map[uint8]string{0: "auto", 1: "cooling only", 2: "heating only"}},
		{108, "DPT_ValveMode", "valve mode", map[uint8]string{1: "heat stage A", 2: "heat stage B", 3: "cool stage A", 4: "cool stage B", 5: "heat/cool"}},
		// The published list gives 3 and 4 the same meaning, extract air.
		{109, "DPT_DamperMode", "damper mode", map[uint8]string{1: "fresh air", 2: "supply air", 3: "extract air", 4: "extract air (4)"}},
		{110, "DPT_HeaterMode", "heater mode", map[uint8]string{1: "heat stage A on/off", 2: "heat stage A proportional", 3: "heat stage B proportional"}},
		{111, "DPT_FanMode", "fan mode", map[uint8]string{0: "not running", 1: "permanently running", 2: "running in intervals"}},
		{112, "DPT_MasterSlaveMode", "master/slave mode", map[uint8]string{0: "autonomous", 1: "master", 2: "slave"}},
		{113, "DPT_StatusRoomSetp", "room setpoint status", map[uint8]string{0: "normal setpoint", 1: "alternative setpoint", 2: "building protection setpoint"}},
		{114, "DPT_Metering_DeviceType", "metering device type", map[uint8]string{
			0: "other device", 1: "oil meter", 2: "electricity meter", 3: "gas device", 4: "heat meter", 5: "steam meter",
			6: "warm water meter", 7: "water meter", 8: "heat cost allocator", 10: "cooling load meter (outlet)",
			11: "cooling load meter (inlet)", 12: "heat (inlet)", 13: "heat and cool", 32: "breaker (electricity)",
			33: "valve (gas or water)", 40: "waste water meter", 41: "garbage", 255: "void device type"}},
		{115, "DPT_HumDehumMode", "humidification/dehumidification mode", map[uint8]string{0: "inactive", 1: "humidification", 2: "dehumidification"}},
		{116, "DPT_EnableHCStage", "enable heating/cooling stage", map[uint8]string{0: "disabled", 1: "enable stage A", 2: "enable stage B", 3: "enable both stages"}},
		{120, "DPT_ADAType", "air damper actuator type", map[uint8]string{1: "air damper", 2: "VAV"}},
		{121, "DPT_BackupMode", "backup mode", map[uint8]string{0: "backup value", 1: "keep last state"}},
		{122, "DPT_StartSynchronization", "start synchronization type", map[uint8]string{0: "position unchanged", 1: "single close", 2: "single open"}},
		{600, "DPT_Behaviour_Lock_Unlock", "behaviour on lock/unlock", map[uint8]string{
			0: "off", 1: "on", 2: "no change", 3: "value of additional parameter", 4: "memory function value", 5: "updated value",
			6: "value before locking"}},
		{601, "DPT_Behaviour_Bus_Power_Up_Down", "behaviour on bus power up/down", map[uint8]string{
			0: "off", 1: "on", 2: "no change", 3: "value of additional parameter", 4: "last value before bus power down"}},
		{602, "DPT_DALI_Fade_Time", "DALI fade time", map[uint8]string{
			0: "0 s", 1: "0.7 s", 2: "1.0 s", 3: "1.4 s", 4: "2.0 s", 5: "2.8 s", 6: "4.0 s", 7: "5.7 s", 8: "8.0 s",
			9: "11.3 s", 10: "16.0 s", 11: "22.6 s", 12: "32.0 s", 13: "45.3 s", 14: "64.0 s", 15: "90.5 s"}},
		{603, "DPT_BlinkingMode", "blinking mode", map[uint8]string{0: "blinking disabled", 1: "without acknowledge", 2: "blinking with acknowledge"}},
		{604, "DPT_LightControlMode", "light control mode", map[uint8]string{0: "automatic light control", 1: "manual light control"}},
		{605, "DPT_SwitchPBModel", "push button switch model", map[uint8]string{1: "one push button", 2: "two push buttons"}},
		{606, "DPT_PBAction", "push button action", map[uint8]string{0: "inactive", 1: "switch off", 2: "switch on", 3: "inverse of on/off info"}},
		{607, "DPT_DimmPBModel", "push button dimming model", map[uint8]string{
			1: "one push button", 2: "one push button on/dim up", 3: "one push button off/dim down", 4: "two push buttons"}},
		{608, "DPT_SwitchOnMode", "switch on mode", map[uint8]string{0: "last actual value", 1: "value of additional parameter", 2: "last received absolute set value"}},
		{609, "DPT_LoadTypeSet", "load type", map[uint8]string{
			0: "automatic", 1: "leading edge (inductive load)", 2: "trailing edge (capacitive load)",
			3: "switch mode only (non-dimmable load)", 4: "automatic once", 5: "CFL leading edge", 6: "CFL trailing edge",
			7: "LED leading edge", 8: "LED trailing edge"}},
		// The published list gives 3 and 255 the same meaning.
		{610, "DPT_LoadTypeDetected", "detected load type", map[uint8]string{
			0: "undefined", 1: "leading edge (inductive load)", 2: "trailing edge (capacitive load)",
			3: "detection not possible or error", 4: "calibration pending", 5: "CFL leading edge", 6: "CFL trailing edge",
			7: "LED leading edge", 8: "LED trailing edge", 255: "detection not possible or error (255)"}},
		{611, "DPT_Converter_Test_Control", "converter test control", map[uint8]string{
			1: "start function test", 2: "start duration test", 3: "start partial duration test", 4: "stop test",
			5: "reset function test done flag", 6: "reset duration test done flag"}},
		{612, "DPT_Converter_Control", "converter control", map[uint8]string{
			0: "restore factory default settings", 1: "go to rest mode", 2: "go to inhibit mode", 3: "re-light/reset inhibit", 4: "reset lamp time"}},
		{801, "DPT_SABExcept_Behaviour", "sunblind actuator behaviour on exception", map[uint8]string{
			0: "up", 1: "down", 2: "no change", 3: "value of additional parameter", 4: "stop"}},
		{802, "DPT_SABBehaviour_Lock_Unlock", "sunblind actuator behaviour on lock/unlock", map[uint8]string{
			0: "up", 1: "down", 2: "no change", 3: "value of additional parameter", 4: "stop", 5: "updated value", 6: "value before locking"}},
		{803, "DPT_SSSBMode", "sunblind push button mode", map[uint8]string{
			1: "one push button", 2: "one push button up/step up", 3: "one push button down/step down", 4: "two push buttons"}},
		{804, "DPT_BlindsControlMode", "blinds control mode", map[uint8]string{0: "automatic control", 1: "manual control"}},
		{1000, "DPT_CommMode", "communication mode", map[uint8]string{
			0: "data link layer", 1: "data link layer busmonitor", 2: "data link layer raw frames", 6: "cEMI transport layer", 255: "no layer"}},
		{1001, "DPT_AddInfoTypes", "additional information type", map[uint8]string{
			1: "PL medium domain address", 2: "RF control octet and serial number or DoA", 3: "busmonitor error flags",
			4: "relative timestamp", 5: "time delay", 6: "extended relative timestamp", 7: "BiBat information"}},
		{1002, "DPT_RF_ModeSelect", "RF mode selection", map[uint8]string{0: "asynchronous", 1: "asynchronous + BiBat master", 2: "asynchronous + BiBat slave"}},
		{1003, "DPT_RF_FilterSelect", "RF filter selection", map[uint8]string{
			0: "no filtering", 1: "domain address", 2: "serial number table", 3: "domain address and serial number"}},
		{1219, "DPT_EVSEMode_1", "EV charging control pilot state", map[uint8]string{
			0: "standby", 1: "vehicle detected", 2: "ready charging", 3: "charging with ventilation", 4: "finished",
			6: "unavailable", 7: "error", 8: "suspended EVSE", 9: "suspended EV"}},
		{1220, "DPT_EVSEMode_2", "EV charging OCPP state", map[uint8]string{
			0: "charging", 1: "EV connected", 2: "suspended EV", 3: "suspended EVSE", 4: "idle", 5: "available",
			6: "occupied", 8: "unavailable", 9: "faulted"}},
		{1221, "DPT_EVSEMode_3", "EV charging error code", map[uint8]string{
			0: "connector lock failure", 1: "EV communication error", 2: "ground failure", 3: "high temperature",
			4: "internal error", 5: "local list conflict", 6: "no error"}},
	} {
		register(&Type{ID: ID{20, e.sub}, Name: e.name, Description: e.desc, Bits: 8, Kind: KindEnum, Enum: e.values, codec: enumCodec})
	}

	// DPT 23: 2-bit enumerations.
	for _, e := range []struct {
		sub        uint16
		name, desc string
		values     map[uint8]string
	}{
		{1, "DPT_OnOffAction", "on/off action", map[uint8]string{0: "off", 1: "on", 2: "off/on", 3: "on/off"}},
		{2, "DPT_Alarm_Reaction", "alarm reaction", map[uint8]string{0: "no alarm used", 1: "alarm position up", 2: "alarm position down"}},
		{3, "DPT_UpDown_Action", "up/down action", map[uint8]string{0: "up", 1: "down", 2: "up/down", 3: "down/up"}},
		{102, "DPT_HVAC_PB_Action", "HVAC push button action", map[uint8]string{
			0: "comfort/economy", 1: "comfort/nothing", 2: "economy/nothing", 3: "building protection/auto"}},
	} {
		register(&Type{ID: ID{23, e.sub}, Name: e.name, Description: e.desc, Bits: 2, Kind: KindEnum, Enum: e.values, codec: enumCodec})
	}

	// DPT 21, 22: status bit sets (the bits are kept as a number).
	// The individual bits are not named and reserved bits are not checked.
	for _, b := range []struct {
		main, sub  uint16
		name, desc string
	}{
		{21, 1, "DPT_StatusGen", "general status (bit set)"},
		{21, 2, "DPT_Device_Control", "device control (bit set)"},
		{21, 100, "DPT_ForceSign", "forcing signal (bit set)"},
		{21, 101, "DPT_ForceSignCool", "forcing signal cool (bit set)"},
		{21, 102, "DPT_StatusRHC", "room heating controller status (bit set)"},
		{21, 103, "DPT_StatusSDHWC", "solar DHW controller status (bit set)"},
		{21, 104, "DPT_FuelTypeSet", "fuel type set (bit set)"},
		{21, 105, "DPT_StatusRCC", "room cooling controller status (bit set)"},
		{21, 106, "DPT_StatusAHU", "air handling unit status (bit set)"},
		{21, 107, "DPT_CombinedStatus_RTSM", "room temperature setpoint manager combined status (bit set)"},
		{21, 601, "DPT_LightActuatorErrorInfo", "lighting actuator error information (bit set)"},
		{21, 1000, "DPT_RF_ModeInfo", "RF communication mode information (bit set)"},
		{21, 1001, "DPT_RF_FilterInfo", "RF filter information (bit set)"},
		{21, 1010, "DPT_Channel_Activation_8", "activation of 8 channels (bit set)"},
		{21, 1200, "DPT_VirtualDryContact", "virtual dry contacts (bit set)"},
		{21, 1201, "DPT_Phases_Status", "phase status (bit set)"},
		{22, 100, "DPT_StatusDHWC", "DHW controller status (16-bit set)"},
		{22, 101, "DPT_StatusRHCC", "room heating/cooling controller status (16-bit set)"},
		{22, 102, "DPT_CombinedStatus_HVA", "HVAC valve actuator combined status (16-bit set)"},
		{22, 103, "DPT_CombinedStatus_RTC", "room temperature controller combined status (16-bit set)"},
		{22, 1000, "DPT_Media", "supported media (16-bit set)"},
		{22, 1010, "DPT_Channel_Activation_16", "activation of 16 channels (16-bit set)"},
	} {
		register(&Type{ID: ID{b.main, b.sub}, Name: b.name, Description: b.desc, Bits: 8 * int(b.main-20), Kind: KindBits, codec: bitsCodec(int(b.main - 20))})
	}

	// DPT 26.
	register(&Type{ID: ID{26, 1}, Name: "DPT_SceneInfo", Description: "scene information (bit 6: inactive)", Bits: 8, Kind: KindBits, codec: bitsCodec(1)})

	// DPT 25.
	register(&Type{ID: ID{25, 1000}, Name: "DPT_DoubleNibble", Description: "busy and NAK repetitions (0..3 each)", Bits: 8, Kind: KindDoubleNibble, codec: layoutCodec(nibbleFields(3))})

	// DPT 27.
	register(&Type{ID: ID{27, 1}, Name: "DPT_CombinedInfoOnOff", Description: "on/off state of 16 outputs with validity mask", Bits: 32, Kind: KindOnOffInfo, codec: onOffInfoCodec})

	// DPT 29.
	register(&Type{ID: ID{29, 10}, Name: "DPT_ActiveEnergy_V64", Description: "active energy", Unit: "Wh", Bits: 64, Kind: KindSigned, codec: intCodec(8, true, 1)})
	register(&Type{ID: ID{29, 11}, Name: "DPT_ApparantEnergy_V64", Description: "apparent energy", Unit: "VAh", Bits: 64, Kind: KindSigned, codec: intCodec(8, true, 1)})
	register(&Type{ID: ID{29, 12}, Name: "DPT_ReactiveEnergy_V64", Description: "reactive energy", Unit: "VARh", Bits: 64, Kind: KindSigned, codec: intCodec(8, true, 1)})

	// DPT 30.
	register(&Type{ID: ID{30, 1010}, Name: "DPT_Channel_Activation_24", Description: "activation of 24 channels (24-bit set)", Bits: 24, Kind: KindBits, codec: bitsCodec(3)})

	// DPT 206: a mode that applies after a delay. 206.100 and 206.102 have
	// the modes of 20.102 and 20.103 with 0 undefined instead of auto;
	// 206.104 and 206.105 those of 20.003 and 20.002.
	for _, e := range []struct {
		sub        uint16
		name, desc string
		values     map[uint8]string
	}{
		{100, "DPT_HVACModeNext", "time delay and HVAC mode", map[uint8]string{0: "undefined", 1: "comfort", 2: "standby", 3: "economy", 4: "building protection"}},
		{102, "DPT_DHWModeNext", "time delay and DHW mode", map[uint8]string{0: "undefined", 1: "legio protect", 2: "normal", 3: "reduced", 4: "off/frost protect"}},
		{104, "DPT_OccModeNext", "time delay and occupancy mode", map[uint8]string{0: "occupied", 1: "standby", 2: "not occupied"}},
		{105, "DPT_BuildingModeNext", "time delay and building mode", map[uint8]string{0: "building in use", 1: "building not used", 2: "building protection"}},
	} {
		register(&Type{ID: ID{206, e.sub}, Name: e.name, Description: e.desc, Bits: 24, Kind: KindModeNext, Enum: e.values, codec: modeNextCodec})
	}

	// DPT 217.
	register(&Type{ID: ID{217, 1}, Name: "DPT_Version", Description: "version (magic 0..31, version 0..31, revision 0..63)", Bits: 16, Kind: KindVersion, codec: versionCodec})

	// DPT 222, 275: room temperature setpoints (comfort, standby, economy
	// and, for 275, building protection), each a DPT 9 value.
	register(&Type{ID: ID{222, 100}, Name: "DPT_TempRoomSetpSetF16[3]", Description: "room temperature setpoints comfort, standby, economy", Unit: "°C", Bits: 48, Kind: KindSetpoints, Min: -273, Max: max9, HasRange: true, codec: setpointsCodec(3)})
	register(&Type{ID: ID{222, 101}, Name: "DPT_TempRoomSetpSetShiftF16[3]", Description: "room temperature setpoint shifts comfort, standby, economy", Unit: "K", Bits: 48, Kind: KindSetpoints, Min: -670760, Max: max9, HasRange: true, codec: setpointsCodec(3)})
	register(&Type{ID: ID{275, 100}, Name: "DPT_TempRoomSetpSetF16[4]", Description: "room temperature setpoints comfort, standby, economy, building protection", Unit: "°C", Bits: 64, Kind: KindSetpoints, Min: -273, Max: max9, HasRange: true, codec: setpointsCodec(4)})
	register(&Type{ID: ID{275, 101}, Name: "DPT_TempRoomSetpSetShiftF16[4]", Description: "room temperature setpoint shifts comfort, standby, economy, building protection", Unit: "K", Bits: 64, Kind: KindSetpoints, Min: -670760, Max: max9, HasRange: true, codec: setpointsCodec(4)})

	// DPT 219, 225, 229, 230, 235, 236.
	register(&Type{ID: ID{219, 1}, Name: "DPT_AlarmInfo", Description: "alarm information (log number, priority, application area, error class, flags)", Bits: 48, Kind: KindAlarmInfo, codec: layoutCodec(alarmInfoFields)})
	register(&Type{ID: ID{225, 1}, Name: "DPT_Scaling_Speed", Description: "scaling speed (time period in steps of 100 ms, percentage)", Bits: 24, Kind: KindScalingSpeed, codec: layoutCodec(scalingFields(100))})
	register(&Type{ID: ID{225, 2}, Name: "DPT_Scaling_Step_Time", Description: "scaling step time (time period in ms, percentage)", Bits: 24, Kind: KindScalingSpeed, codec: layoutCodec(scalingFields(1))})
	register(&Type{ID: ID{229, 1}, Name: "DPT_MeteringValue", Description: "metering value (counter, value information, status)", Bits: 48, Kind: KindMeteringValue, codec: layoutCodec(meteringFields)})
	register(&Type{ID: ID{230, 1000}, Name: "DPT_MBus_Address", Description: "M-Bus address (manufacturer, identification number, version, medium)", Bits: 64, Kind: KindMBusAddress, codec: layoutCodec(mbusFields)})
	register(&Type{ID: ID{235, 1}, Name: "DPT_Tariff_ActiveEnergy", Description: "active energy (Wh) with tariff", Bits: 48, Kind: KindTariffEnergy, codec: layoutCodec(tariffFields)})
	register(&Type{ID: ID{236, 1}, Name: "DPT_Prioritised_Mode_Control", Description: "prioritised mode control (deactivation, priority 0..7, mode 0..15)", Bits: 8, Kind: KindPriorityControl, codec: layoutCodec(priorityFields)})

	// DALI: 237, 238, 244, 245.
	register(&Type{ID: ID{237, 600}, Name: "DPT_DALI_Control_Gear_Diagnostic", Description: "DALI control gear diagnostic (failures, address)", Bits: 16, Kind: KindDALIGearDiagnostic, codec: layoutCodec(daliGearFields)})
	register(&Type{ID: ID{238, 600}, Name: "DPT_DALI_Diagnostics", Description: "DALI diagnostic (failures, device address)", Bits: 8, Kind: KindDALIDiagnostic, codec: layoutCodec(daliFields)})
	register(&Type{ID: ID{244, 600}, Name: "DPT_Converter_Status", Description: "DALI emergency converter status", Bits: 16, Kind: KindConverterStatus, codec: layoutCodec(converterStatusFields)})
	register(&Type{ID: ID{245, 600}, Name: "DPT_Converter_Test_Result", Description: "DALI emergency converter test result", Bits: 48, Kind: KindConverterTestResult, codec: layoutCodec(converterTestFields)})

	// DPT 240: blinds.
	register(&Type{ID: ID{240, 800}, Name: "DPT_CombinedPosition", Description: "height and slats positions with validity", Bits: 24, Kind: KindCombinedPosition, codec: layoutCodec(positionFields)})

	// DPT 207.600, 241.800, 246.600, 252.600 and 254.600 follow the KNX
	// master data; xknx orders their bits or octets the other way.
	register(&Type{ID: ID{207, 600}, Name: "DPT_StatusLightingActuator", Description: "lighting actuator status (flags, actual value)", Bits: 16, Kind: KindLightingActuatorStatus, codec: layoutCodec(lightingStatusFields)})
	register(&Type{ID: ID{241, 800}, Name: "DPT_StatusSAB", Description: "sunblind and shutter actuator status", Bits: 32, Kind: KindBlindsStatus, codec: layoutCodec(blindsStatusFields)})
	register(&Type{ID: ID{246, 600}, Name: "DPT_Battery_Info", Description: "battery information (failures, charge level)", Bits: 16, Kind: KindBatteryInfo, codec: layoutCodec(batteryFields)})
	register(&Type{ID: ID{252, 600}, Name: "DPT_Relative_Control_RGBW", Description: "relative RGBW control", Bits: 40, Kind: KindRelativeRGBW, codec: layoutCodec(relativeRGBWFields)})
	register(&Type{ID: ID{254, 600}, Name: "DPT_Relative_Control_RGB", Description: "relative RGB control", Bits: 24, Kind: KindRelativeRGB, codec: layoutCodec(relativeRGBFields)})

	// DPT 255.
	register(&Type{ID: ID{255, 1}, Name: "DPT_GeographicalLocation", Description: "geographical location (longitude, latitude in degrees)", Bits: 64, Kind: KindGeoLocation, codec: layoutCodec(geoFields)})

	// DPT 234.
	register(&Type{ID: ID{234, 1}, Name: "DPT_LanguageCodeAlpha2_ASCII", Description: "language code (ISO 639-1, two letters)", Bits: 16, Kind: KindString, codec: alpha2Codec})
	register(&Type{ID: ID{234, 2}, Name: "DPT_RegionCodeAlpha2_ASCII", Description: "region code (ISO 3166-1 alpha-2, two letters)", Bits: 16, Kind: KindString, codec: alpha2Codec})

	// Colours.
	register(&Type{ID: ID{232, 600}, Name: "DPT_Colour_RGB", Description: "RGB colour", Bits: 24, Kind: KindRGB, codec: rgbCodec})
	register(&Type{ID: ID{232, 601}, Name: "DPT_Colour_HSV", Description: "HSV colour", Bits: 24, Kind: KindHSV, codec: layoutCodec(hsvFields)})
	register(&Type{ID: ID{242, 600}, Name: "DPT_Colour_xyY", Description: "colour xyY", Bits: 48, Kind: KindXYY, codec: xyyCodec})
	register(&Type{ID: ID{251, 600}, Name: "DPT_Colour_RGBW", Description: "RGBW colour", Bits: 48, Kind: KindRGBW, codec: rgbwCodec})
	register(&Type{ID: ID{249, 600}, Name: "DPT_Brightness_Colour_Temperature_Transition", Description: "transition to a colour temperature and brightness", Bits: 48, Kind: KindColourTransition, codec: layoutCodec(transitionFields)})
	register(&Type{ID: ID{250, 600}, Name: "DPT_Brightness_Colour_Temperature_Control", Description: "relative colour temperature and brightness control", Bits: 24, Kind: KindColourTemperatureControl, codec: layoutCodec(temperatureControlFields)})

	// The other subtypes of the KNX master data whose format is known
	// (masterdata.go).
	registerMasterData()
}
