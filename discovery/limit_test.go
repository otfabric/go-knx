// SPDX-License-Identifier: MIT

package discovery_test

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/discovery"
	"github.com/otfabric/go-knx/internal/fakeknx"
	"github.com/otfabric/go-knx/internal/leak"
	"github.com/otfabric/go-knx/knxnetip"
)

// A flood of distinct answers ends the search at WithMaxResults, long
// before its timeout, instead of growing the result list.
func TestSearchMaxResults(t *testing.T) {
	leak.Check(t)
	p := fakeknx.Listen(t)
	p.Handle(func(p *fakeknx.Peer, d fakeknx.Datagram) bool {
		req, ok := d.Msg.(*knxnetip.SearchRequest)
		if !ok {
			return false
		}
		for i := range 50 {
			dib := knxnetip.DeviceInfo{Medium: knxnetip.MediumIP, Name: "flood", Multicast: netip.IPv4Unspecified(), Serial: [6]byte{0, 1, 0, 0, 0, byte(i)}}
			p.Send(req.Discovery.Addr, &knxnetip.SearchResponse{Control: p.HPAI(), DIBs: knxnetip.DIBs{dib}})
		}
		return true
	})
	start := time.Now()
	rs, err := discovery.Search(ctx(t), discovery.SearchTo(p.Addr()), discovery.WithMaxResults(3), discovery.WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 3 {
		t.Fatalf("%d results, want 3", len(rs))
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("search took %v: it did not stop at the limit", d)
	}
	if _, err := discovery.Search(ctx(t), discovery.WithMaxResults(0)); !errors.Is(err, knx.ErrInvalidOption) {
		t.Fatalf("WithMaxResults(0): %v", err)
	}
	if discovery.DefaultMaxResults < 1 {
		t.Fatal("no default limit")
	}
}
