// SPDX-License-Identifier: MIT

package dpt_test

import (
	"fmt"

	"github.com/otfabric/go-knx/dpt"
)

func Example() {
	t, err := dpt.Lookup("9.001")
	if err != nil {
		panic(err)
	}
	b, err := t.Encode(21.5)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s: % X\n", t, b)

	v, err := t.Decode([]byte{0x8A, 0x24})
	if err != nil {
		panic(err)
	}
	fmt.Println(t.Format(v))
	// Output:
	// 9.001 DPT_Value_Temp: 0C 33
	// -30 °C
}

func ExampleType_Parse() {
	t := dpt.MustLookup("DPST-1-1")
	v, _ := t.Parse("on")
	b, _ := t.Encode(v)
	fmt.Printf("%s %v % X %v\n", t.Name, v, b, t.Small())

	hvac := dpt.MustLookup("20.102")
	b, _ = hvac.Encode("economy")
	m, _ := hvac.Decode(b)
	fmt.Printf("% X %v\n", b, m)
	// Output:
	// DPT_Switch true 01 true
	// 03 economy
}
