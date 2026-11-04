// SPDX-License-Identifier: MIT

package mgmt_test

import (
	"bytes"
	"testing"

	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/mgmt"
)

// bigProps describes one property with a maximum element count set by
// the test.
type bigProps struct {
	props
	max uint16
}

func (p *bigProps) DescribeProperty(object, pid, index uint8) (mgmt.Description, bool) {
	return mgmt.Description{PID: 76, Index: 1, Type: 0x02, MaxElements: p.max, Access: 0xF0}, true
}

// The maximum element count is 12 bits on the wire. A larger value used
// to be masked: 4096 elements were described as 0, 4097 as 1. It is now
// sent as 4095.
func TestDescriptionMaxElementsSaturates(t *testing.T) {
	for _, c := range []struct {
		max    uint16
		hi, lo byte
	}{
		{0x0FFF, 0x0F, 0xFF},
		{0x1000, 0x0F, 0xFF},
		{0x1001, 0x0F, 0xFF},
		{0xFFFF, 0x0F, 0xFF},
		{0x0123, 0x01, 0x23},
	} {
		r := &mgmt.Responder{Address: dev, Properties: &bigProps{max: c.max}, Code: cemi.LDataInd}
		out := r.Handle(frame(data, apdu.PropertyDescriptionReadService, 0, 76, 0))
		want := []byte{0, 76, 1, 0x02, c.hi, c.lo, 0xF0}
		if d := parse(t, out[0]); !bytes.Equal(d.Data, want) {
			t.Errorf("MaxElements %d: % X, want % X", c.max, d.Data, want)
		}
	}
}
