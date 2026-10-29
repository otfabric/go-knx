// SPDX-License-Identifier: MIT

package knxnetip_test

import (
	"fmt"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/knxnetip"
)

// Build a TUNNELLING_REQUEST that writes "on" to group address 1/2/3.
func Example_tunnellingRequest() {
	tpdu, err := apdu.GroupValueWrite(apdu.GroupValue{Data: []byte{1}, Small: true})
	if err != nil {
		panic(err)
	}
	f := cemi.NewGroupFrame(cemi.LDataReq, 0, knx.MustParseGroupAddress("1/2/3"), knx.PriorityLow, tpdu)
	c, err := cemi.Marshal(f)
	if err != nil {
		panic(err)
	}
	frame, err := knxnetip.Marshal(&knxnetip.TunnellingRequest{Channel: 21, Seq: 0, CEMI: c})
	if err != nil {
		panic(err)
	}
	fmt.Printf("% X\n", frame)

	m, _ := knxnetip.Parse(frame)
	fmt.Println(m.Service())
	// Output:
	// 06 10 04 20 00 15 04 15 00 00 11 00 BC E0 00 00 0A 03 01 00 81
	// TUNNELLING_REQUEST
}
