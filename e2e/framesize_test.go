// SPDX-License-Identifier: MIT

package e2e

import (
	"errors"
	"testing"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/client"
	"github.com/otfabric/go-knx/tunnel"
)

// A frame that fits a plain KNXnet/IP datagram but not once secured is
// refused with knx.ErrInvalidValue; the secure tunnel stays usable.
func TestSecureFrameTooLongKeepsConnection(t *testing.T) {
	addr := secureServer(t)
	c := ctx(t)
	a, err := client.DialTunnel(c, addr, []tunnel.Option{cred(t, 3, "secret3", "")})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	tc := a.Link().(*tunnel.Conn)
	// 10 octets of KNXnet/IP headers + 1000 fit 1024; the SECURE_WRAPPER
	// adds 38.
	err = tc.Send(c, &cemi.Raw{MsgCode: cemi.LRawReq, Data: make([]byte, 998)})
	if !errors.Is(err, knx.ErrInvalidValue) || errors.Is(err, knx.ErrConnectionLost) {
		t.Fatalf("oversized secured frame: %v", err)
	}
	if err := a.GroupWrite(c, knx.MustParseGroupAddress("1/2/3"), true, client.WithDPT("1.001")); err != nil {
		t.Fatalf("write after the refused frame: %v", err)
	}
}
