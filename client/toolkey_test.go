// SPDX-License-Identifier: MIT

package client_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/apdu"
	"github.com/otfabric/go-knx/client"
	"github.com/otfabric/go-knx/datasecure"
	"github.com/otfabric/go-knx/internal/leak"
)

// A Data Secure table for a tool key that cannot be made (datasecure.NewTable
// refuses a system clock before 2018-01-05): DeviceWithToolKey returns the
// error and no Device, and leaves a Device of the address in place; a
// Device made with WithToolKey returns the error from every request and
// sends nothing.
func TestToolKeyTableError(t *testing.T) {
	leak.Check(t)
	errClock := fmt.Errorf("%w: datasecure: system clock is before the sequence epoch", knx.ErrInvalidValue)
	defer client.SetToolTable(func() (*datasecure.Table, error) { return nil, errClock })()
	l := newLink()
	c := client.New(l, client.WithSource(src))
	defer c.Close()
	kept := c.Device(serverAddress)
	d, err := c.DeviceWithToolKey(serverAddress, datasecure.Key{1})
	if d != nil || !errors.Is(err, errClock) {
		t.Fatalf("DeviceWithToolKey = %v, %v; want no Device and the error of the table", d, err)
	}
	scripted(l, func(l *link, tp apdu.TPDU, _ int) {
		if tp.APCI == apdu.DeviceDescriptorReadService {
			l.in <- from(apdu.TPDU{APCI: apdu.DeviceDescriptorResponseService, Data: []byte{0x07, 0xB0}})
		}
	})
	if v, err := kept.DescriptorRead(ctx(t)); err != nil || v != 0x07B0 {
		t.Fatalf("the Device made before DeviceWithToolKey failed: %04X, %v; want 07B0", v, err)
	}
	sent := sentFrames(l)

	d = c.Device(serverAddress, client.WithToolKey(datasecure.Key{1}))
	for name, call := range deviceCalls {
		if err := call(ctx(t), d); !errors.Is(err, errClock) {
			t.Errorf("%s of a Device whose table could not be made = %v, want the error of the table", name, err)
		}
	}
	if n := sentFrames(l); n != sent {
		t.Errorf("%d frames sent by a Device whose table could not be made, want 0", n-sent)
	}
	if err := d.Close(); err != nil {
		t.Errorf("Close = %v", err)
	}
}

// DeviceWithToolKey secures the access like WithToolKey: with the client's
// own Data Secure table it uses that table and makes none.
func TestDeviceWithToolKey(t *testing.T) {
	leak.Check(t)
	c, _ := newClient(t, client.WithSource(src))
	d, err := c.DeviceWithToolKey(serverAddress, datasecure.Key{1}, client.Connected())
	if err != nil || d == nil || !d.Secured() || d.Address() != serverAddress {
		t.Fatalf("DeviceWithToolKey = %v, %v; want a secured Device of %s", d, err, serverAddress)
	}
	d.Close()

	errClock := errors.New("not called")
	defer client.SetToolTable(func() (*datasecure.Table, error) { return nil, errClock })()
	tab, err := datasecure.NewTable(nil, nil, 50)
	if err != nil {
		t.Fatal(err)
	}
	sc, _ := newClient(t, client.WithSource(src), client.WithDataSecure(tab))
	d, err = sc.DeviceWithToolKey(serverAddress, datasecure.Key{1})
	if err != nil || !d.Secured() {
		t.Fatalf("DeviceWithToolKey with the client's table = %v, %v", d, err)
	}
	if _, ok := tab.ToolKey(serverAddress); !ok {
		t.Fatal("the tool key is not in the client's table")
	}
}
