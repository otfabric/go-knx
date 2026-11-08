// SPDX-License-Identifier: MIT

package cemi_test

import (
	"bytes"
	"testing"

	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/internal/capture"
)

// TestCaptureTP1 decodes every frame recorded on the TP1 line of a house
// (knx-datasets: normal operation, line scan, device info) with ParseTP1,
// check octet included, and encodes it again with TP1Frame to the
// recorded octets, link-layer repetitions (control field 0x90 and 0x9C)
// included; the L_Data.ind it decodes to encodes as cEMI and decodes to
// the same frame.
func TestCaptureTP1(t *testing.T) {
	want := map[string][2]int{ // frames, repeated
		"knx-datasets/unknown_residential-tp1_all-knx.pcapng":         {379875, 10},
		"knx-datasets/attack-tool_residential-tp1_line-scan.pcapng":   {381524, 994},
		"knx-datasets/attack-tool_residential-tp1_device-info.pcapng": {388695, 5410},
	}
	for rel, w := range want {
		f, err := capture.Load(rel)
		if err != nil {
			t.Fatal(err)
		}
		repeated := 0
		for _, fr := range f.TP {
			ld, err := cemi.ParseTP1(fr.Data)
			if err != nil {
				t.Fatalf("%s frame %d: % X: %v", rel, fr.Frame, fr.Data, err)
			}
			if ld.Repeat() {
				repeated++
			}
			b, err := cemi.TP1Frame(ld)
			if err != nil || !bytes.Equal(b, fr.Data) {
				t.Fatalf("%s frame %d: % X encodes to % X (%v)", rel, fr.Frame, fr.Data, b, err)
			}
			c, err := cemi.Marshal(ld)
			if err != nil {
				t.Fatal(err)
			}
			g, err := cemi.Parse(c)
			if err != nil {
				t.Fatalf("%s frame %d: cEMI % X: %v", rel, fr.Frame, c, err)
			}
			if again, _ := cemi.Marshal(g); !bytes.Equal(again, c) {
				t.Fatalf("%s frame %d: cEMI % X, again % X", rel, fr.Frame, c, again)
			}
		}
		if len(f.TP) != w[0] || repeated != w[1] {
			t.Errorf("%s: %d frames, %d repeated; want %v", rel, len(f.TP), repeated, w)
		}
	}
}
