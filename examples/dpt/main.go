// SPDX-License-Identifier: MIT

// Command dpt encodes and decodes datapoint values.
package main

import (
	"fmt"
	"log"

	"github.com/otfabric/go-knx/dpt"
)

func main() {
	for _, c := range []struct {
		id    string
		value any
	}{
		{"1.001", true},
		{"5.001", 75.0},
		{"9.001", 21.5},
		{"14.056", 1234.5},
		{"10.001", dpt.TimeOfDay{Weekday: 4, Hour: 12, Minute: 30}},
		{"20.102", "economy"},
		{"232.600", dpt.RGB{R: 255, G: 128}},
	} {
		t := dpt.MustLookup(c.id)
		b, err := t.Encode(c.value)
		if err != nil {
			log.Fatal(err)
		}
		v, err := t.Decode(b)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%-8s %-30s % X -> %s\n", t.ID, t.Name, b, t.Format(v))
	}
}
