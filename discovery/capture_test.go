// SPDX-License-Identifier: MIT

package discovery_test

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/otfabric/go-knx/discovery"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/knxnetip"
)

// abbSearchResponseExt is the SEARCH_RESPONSE_EXTENDED an ABB IP-Router
// IPR/S sent in testdata/captures/wireshark-14825
// (test-tool_abb-ipr-s_01-core.txt, frame 1048), with a TUNNELLING_INFO
// and a SECURED_SERVICE_FAMILIES block of another layout.
const abbSearchResponseExt = "0610020c007b0801c0a8000a0e573601020021000000000281fdff50e000170c000cde02808e" +
	"4142422049502d526f75746572204950522f5300000000000000000000000e02020103020402050107010901080800000038091a" +
	"160721010000210200002103000021040000210500000b06000000000000000001"

// TestCaptureExtendedSearchABB: an extended search answered with the
// router's recorded response finds the router. go-knx used to refuse the
// whole response for its malformed optional blocks and found nothing.
func TestCaptureExtendedSearchABB(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	recorded, _ := hex.DecodeString(abbSearchResponseExt)
	p.Handle(func(p *fakeknx.Peer, d fakeknx.Datagram) bool {
		if _, ok := d.Msg.(*knxnetip.SearchRequestExt); !ok {
			return false
		}
		p.SendRaw(d.From, recorded)
		return true
	})
	rs, err := discovery.Search(ctx(t), discovery.WithUnicast(p.String()), discovery.WithNAT(true),
		discovery.WithExtended(), discovery.WithTimeout(300*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 || !rs[0].Extended || rs[0].Device().Name != "ABB IP-Router IPR/S" {
		t.Fatalf("results %+v", rs)
	}
	if v, ok := rs[0].Services().Version(knxnetip.FamilyTunnelling); !ok || v != 2 {
		t.Fatalf("services %+v", rs[0].Services())
	}
}
