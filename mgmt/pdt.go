// SPDX-License-Identifier: MIT

package mgmt

import "fmt"

// PDT is a property datatype: the 6-bit type of a property's elements in
// a property description. The identifiers are those of the KNX
// standardized identifier tables; values without a name here are
// reserved.
type PDT uint8

// Property datatypes.
const (
	PDTControl             PDT = 0x00
	PDTChar                PDT = 0x01
	PDTUnsignedChar        PDT = 0x02
	PDTInt                 PDT = 0x03
	PDTUnsignedInt         PDT = 0x04
	PDTKNXFloat            PDT = 0x05
	PDTDate                PDT = 0x06
	PDTTime                PDT = 0x07
	PDTLong                PDT = 0x08
	PDTUnsignedLong        PDT = 0x09
	PDTFloat               PDT = 0x0A
	PDTDouble              PDT = 0x0B
	PDTCharBlock           PDT = 0x0C
	PDTPollGroupSetting    PDT = 0x0D
	PDTShortCharBlock      PDT = 0x0E
	PDTDateTime            PDT = 0x0F
	PDTVariableLength      PDT = 0x10
	PDTGeneric01           PDT = 0x11
	PDTGeneric02           PDT = 0x12
	PDTGeneric03           PDT = 0x13
	PDTGeneric04           PDT = 0x14
	PDTGeneric05           PDT = 0x15
	PDTGeneric06           PDT = 0x16
	PDTGeneric07           PDT = 0x17
	PDTGeneric08           PDT = 0x18
	PDTGeneric09           PDT = 0x19
	PDTGeneric10           PDT = 0x1A
	PDTGeneric11           PDT = 0x1B
	PDTGeneric12           PDT = 0x1C
	PDTGeneric13           PDT = 0x1D
	PDTGeneric14           PDT = 0x1E
	PDTGeneric15           PDT = 0x1F
	PDTGeneric16           PDT = 0x20
	PDTGeneric17           PDT = 0x21
	PDTGeneric18           PDT = 0x22
	PDTGeneric19           PDT = 0x23
	PDTGeneric20           PDT = 0x24
	PDTUTF8                PDT = 0x2F
	PDTVersion             PDT = 0x30
	PDTAlarmInfo           PDT = 0x31
	PDTBinaryInformation   PDT = 0x32
	PDTBitset8             PDT = 0x33
	PDTBitset16            PDT = 0x34
	PDTEnum8               PDT = 0x35
	PDTScaling             PDT = 0x36
	PDTNotEditableVariable PDT = 0x3C // PDT_NE_VL
	PDTNotEditableFixed    PDT = 0x3D // PDT_NE_FL
	PDTFunction            PDT = 0x3E
	PDTEscape              PDT = 0x3F
)

// pdtInfo is the name and element size (0: not fixed by the type) of
// the named datatypes other than the generic ones.
var pdtInfo = map[PDT]struct {
	name string
	size int
}{
	PDTControl:             {"PDT_CONTROL", 0},
	PDTChar:                {"PDT_CHAR", 1},
	PDTUnsignedChar:        {"PDT_UNSIGNED_CHAR", 1},
	PDTInt:                 {"PDT_INT", 2},
	PDTUnsignedInt:         {"PDT_UNSIGNED_INT", 2},
	PDTKNXFloat:            {"PDT_KNX_FLOAT", 2},
	PDTDate:                {"PDT_DATE", 3},
	PDTTime:                {"PDT_TIME", 3},
	PDTLong:                {"PDT_LONG", 4},
	PDTUnsignedLong:        {"PDT_UNSIGNED_LONG", 4},
	PDTFloat:               {"PDT_FLOAT", 4},
	PDTDouble:              {"PDT_DOUBLE", 8},
	PDTCharBlock:           {"PDT_CHAR_BLOCK", 10},
	PDTPollGroupSetting:    {"PDT_POLL_GROUP_SETTING", 3},
	PDTShortCharBlock:      {"PDT_SHORT_CHAR_BLOCK", 5},
	PDTDateTime:            {"PDT_DATE_TIME", 8},
	PDTVariableLength:      {"PDT_VARIABLE_LENGTH", 0},
	PDTUTF8:                {"PDT_UTF8", 0},
	PDTVersion:             {"PDT_VERSION", 2},
	PDTAlarmInfo:           {"PDT_ALARM_INFO", 6},
	PDTBinaryInformation:   {"PDT_BINARY_INFORMATION", 1},
	PDTBitset8:             {"PDT_BITSET8", 1},
	PDTBitset16:            {"PDT_BITSET16", 2},
	PDTEnum8:               {"PDT_ENUM8", 1},
	PDTScaling:             {"PDT_SCALING", 1},
	PDTNotEditableVariable: {"PDT_NE_VL", 0},
	PDTNotEditableFixed:    {"PDT_NE_FL", 0},
	PDTFunction:            {"PDT_FUNCTION", 0},
	PDTEscape:              {"PDT_ESCAPE", 0},
}

// generic reports whether p is one of PDT_GENERIC_01 to _20, whose
// element size is their number of octets.
func (p PDT) generic() bool { return p >= PDTGeneric01 && p <= PDTGeneric20 }

// Size returns the octets of one element of a property of this type.
// ok is false when the type alone does not fix it (control, variable
// length, UTF-8, not editable, function, escape) and for reserved
// values.
func (p PDT) Size() (n int, ok bool) {
	if p.generic() {
		return int(p-PDTGeneric01) + 1, true
	}
	i, known := pdtInfo[p]
	return i.size, known && i.size > 0
}

// String returns the identifier's name, such as PDT_UNSIGNED_CHAR, or
// PDT(0xNN) for a reserved value.
func (p PDT) String() string {
	if p.generic() {
		return fmt.Sprintf("PDT_GENERIC_%02d", int(p-PDTGeneric01)+1)
	}
	if i, ok := pdtInfo[p]; ok {
		return i.name
	}
	return fmt.Sprintf("PDT(0x%02X)", uint8(p))
}
