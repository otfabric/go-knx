// SPDX-License-Identifier: MIT

package apdu

import "fmt"

// APCI is a 10-bit application layer service code. For services with a
// 4-bit code the low 6 bits are zero here; their parameter is
// [TPDU.Short].
type APCI uint16

// Application layer services.
const (
	GroupValueReadService                        APCI = 0x000
	GroupValueResponseService                    APCI = 0x040
	GroupValueWriteService                       APCI = 0x080
	IndividualAddressWriteService                APCI = 0x0C0
	IndividualAddressReadService                 APCI = 0x100
	IndividualAddressResponseService             APCI = 0x140
	ADCReadService                               APCI = 0x180
	ADCResponseService                           APCI = 0x1C0
	SystemNetworkParameterReadService            APCI = 0x1C8
	SystemNetworkParameterResponseService        APCI = 0x1C9
	SystemNetworkParameterWriteService           APCI = 0x1CA
	MemoryExtendedWriteService                   APCI = 0x1FB
	MemoryExtendedWriteResponseService           APCI = 0x1FC
	MemoryExtendedReadService                    APCI = 0x1FD
	MemoryExtendedReadResponseService            APCI = 0x1FE
	MemoryReadService                            APCI = 0x200
	MemoryResponseService                        APCI = 0x240
	MemoryWriteService                           APCI = 0x280
	UserMemoryReadService                        APCI = 0x2C0
	UserMemoryResponseService                    APCI = 0x2C1
	UserMemoryWriteService                       APCI = 0x2C2
	UserManufacturerInfoReadService              APCI = 0x2C5
	UserManufacturerInfoResponseService          APCI = 0x2C6
	FunctionPropertyCommandService               APCI = 0x2C7
	FunctionPropertyStateReadService             APCI = 0x2C8
	FunctionPropertyStateResponseService         APCI = 0x2C9
	DeviceDescriptorReadService                  APCI = 0x300
	DeviceDescriptorResponseService              APCI = 0x340
	RestartService                               APCI = 0x380
	RestartResponseService                       APCI = 0x3A1
	AuthorizeRequestService                      APCI = 0x3D1
	AuthorizeResponseService                     APCI = 0x3D2
	KeyWriteService                              APCI = 0x3D3
	KeyResponseService                           APCI = 0x3D4
	PropertyValueReadService                     APCI = 0x3D5
	PropertyValueResponseService                 APCI = 0x3D6
	PropertyValueWriteService                    APCI = 0x3D7
	PropertyDescriptionReadService               APCI = 0x3D8
	PropertyDescriptionResponseService           APCI = 0x3D9
	NetworkParameterReadService                  APCI = 0x3DA
	NetworkParameterResponseService              APCI = 0x3DB
	IndividualAddressSerialNumberReadService     APCI = 0x3DC
	IndividualAddressSerialNumberResponseService APCI = 0x3DD
	IndividualAddressSerialNumberWriteService    APCI = 0x3DE
	DomainAddressWriteService                    APCI = 0x3E0
	DomainAddressReadService                     APCI = 0x3E1
	DomainAddressResponseService                 APCI = 0x3E2
	DomainAddressSelectiveReadService            APCI = 0x3E3
	NetworkParameterWriteService                 APCI = 0x3E4
	LinkReadService                              APCI = 0x3E5
	LinkResponseService                          APCI = 0x3E6
	LinkWriteService                             APCI = 0x3E7
	GroupPropValueReadService                    APCI = 0x3E8
	GroupPropValueResponseService                APCI = 0x3E9
	GroupPropValueWriteService                   APCI = 0x3EA
	GroupPropValueInfoReportService              APCI = 0x3EB
	DomainAddressSerialNumberReadService         APCI = 0x3EC
	DomainAddressSerialNumberResponseService     APCI = 0x3ED
	DomainAddressSerialNumberWriteService        APCI = 0x3EE
	FileStreamInfoReportService                  APCI = 0x3F0
	SecureService                                APCI = 0x3F1
)

var apciNames = map[APCI]string{
	GroupValueReadService: "A_GroupValue_Read", GroupValueResponseService: "A_GroupValue_Response",
	GroupValueWriteService: "A_GroupValue_Write", IndividualAddressWriteService: "A_IndividualAddress_Write",
	IndividualAddressReadService: "A_IndividualAddress_Read", IndividualAddressResponseService: "A_IndividualAddress_Response",
	ADCReadService: "A_ADC_Read", ADCResponseService: "A_ADC_Response",
	SystemNetworkParameterReadService: "A_SystemNetworkParameter_Read", SystemNetworkParameterResponseService: "A_SystemNetworkParameter_Response",
	SystemNetworkParameterWriteService: "A_SystemNetworkParameter_Write",
	MemoryExtendedWriteService:         "A_MemoryExtended_Write", MemoryExtendedWriteResponseService: "A_MemoryExtended_WriteResponse",
	MemoryExtendedReadService: "A_MemoryExtended_Read", MemoryExtendedReadResponseService: "A_MemoryExtended_ReadResponse",
	MemoryReadService: "A_Memory_Read", MemoryResponseService: "A_Memory_Response", MemoryWriteService: "A_Memory_Write",
	UserMemoryReadService: "A_UserMemory_Read", UserMemoryResponseService: "A_UserMemory_Response", UserMemoryWriteService: "A_UserMemory_Write",
	UserManufacturerInfoReadService: "A_UserManufacturerInfo_Read", UserManufacturerInfoResponseService: "A_UserManufacturerInfo_Response",
	FunctionPropertyCommandService: "A_FunctionPropertyCommand", FunctionPropertyStateReadService: "A_FunctionPropertyState_Read",
	FunctionPropertyStateResponseService: "A_FunctionPropertyState_Response",
	DeviceDescriptorReadService:          "A_DeviceDescriptor_Read", DeviceDescriptorResponseService: "A_DeviceDescriptor_Response",
	RestartService: "A_Restart", RestartResponseService: "A_Restart_Response",
	AuthorizeRequestService: "A_Authorize_Request", AuthorizeResponseService: "A_Authorize_Response",
	KeyWriteService: "A_Key_Write", KeyResponseService: "A_Key_Response",
	PropertyValueReadService: "A_PropertyValue_Read", PropertyValueResponseService: "A_PropertyValue_Response",
	PropertyValueWriteService: "A_PropertyValue_Write", PropertyDescriptionReadService: "A_PropertyDescription_Read",
	PropertyDescriptionResponseService: "A_PropertyDescription_Response",
	NetworkParameterReadService:        "A_NetworkParameter_Read", NetworkParameterResponseService: "A_NetworkParameter_Response",
	IndividualAddressSerialNumberReadService:     "A_IndividualAddressSerialNumber_Read",
	IndividualAddressSerialNumberResponseService: "A_IndividualAddressSerialNumber_Response",
	IndividualAddressSerialNumberWriteService:    "A_IndividualAddressSerialNumber_Write",
	DomainAddressWriteService:                    "A_DomainAddress_Write", DomainAddressReadService: "A_DomainAddress_Read",
	DomainAddressResponseService: "A_DomainAddress_Response", DomainAddressSelectiveReadService: "A_DomainAddressSelective_Read",
	NetworkParameterWriteService: "A_NetworkParameter_Write", LinkReadService: "A_Link_Read", LinkResponseService: "A_Link_Response",
	LinkWriteService: "A_Link_Write", GroupPropValueReadService: "A_GroupPropValue_Read", GroupPropValueResponseService: "A_GroupPropValue_Response",
	GroupPropValueWriteService: "A_GroupPropValue_Write", GroupPropValueInfoReportService: "A_GroupPropValue_InfoReport",
	DomainAddressSerialNumberReadService: "A_DomainAddressSerialNumber_Read", DomainAddressSerialNumberResponseService: "A_DomainAddressSerialNumber_Response",
	DomainAddressSerialNumberWriteService: "A_DomainAddressSerialNumber_Write", FileStreamInfoReportService: "A_FileStream_InfoReport",
	SecureService: "SecureService",
}

// String names the service, such as "A_GroupValue_Write", or "APCI(0x%03X)".
func (a APCI) String() string {
	if n, ok := apciNames[a]; ok {
		return n
	}
	return fmt.Sprintf("APCI(0x%03X)", uint16(a))
}

// Has6BitData reports whether the service has a 4-bit code with a 6-bit
// parameter in the low bits (a is the 10-bit value of the octets).
func (a APCI) Has6BitData() bool {
	switch a & 0x3C0 {
	case GroupValueReadService, GroupValueResponseService, GroupValueWriteService,
		ADCReadService, MemoryReadService, MemoryResponseService, MemoryWriteService,
		DeviceDescriptorReadService, DeviceDescriptorResponseService:
		// ADC_Response 0x1C0 shares its 4 bits with the 10-bit system
		// network parameter and extended memory services.
		return true
	case ADCResponseService:
		return a&0x3F < 0x08
	}
	return false
}
