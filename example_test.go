// SPDX-License-Identifier: MIT

package knx_test

import (
	"fmt"

	"github.com/otfabric/go-knx"
)

func ExampleParseGroupAddress() {
	for _, s := range []string{"1/2/3", "1/515", "2563"} {
		g, err := knx.ParseGroupAddress(s)
		if err != nil {
			panic(err)
		}
		fmt.Println(s, "=", g, g.Format(knx.GroupTwoLevel), g.Format(knx.GroupFree))
	}
	_, err := knx.ParseGroupAddress("32/0/0")
	fmt.Println(err)
	// Output:
	// 1/2/3 = 1/2/3 1/515 2563
	// 1/515 = 1/2/3 1/515 2563
	// 2563 = 1/2/3 1/515 2563
	// knx: invalid address: group address "32/0/0": main is 0..31, middle 0..7, sub 0..255
}

func ExampleParseIndividualAddress() {
	a, err := knx.ParseIndividualAddress("1.1.10")
	if err != nil {
		panic(err)
	}
	fmt.Println(a.Area(), a.Line(), a.Device())
	fmt.Printf("0x%04X\n", a.Uint16())
	// Output:
	// 1 1 10
	// 0x110A
}
