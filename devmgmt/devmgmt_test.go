// SPDX-License-Identifier: MIT

package devmgmt_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/cemi"
	"github.com/otfabric/go-knx/devmgmt"
	"github.com/otfabric/go-knx/server"
)

func TestPropertyAccess(t *testing.T) {
	s, err := server.New(server.WithListenAddr("127.0.0.1:0"), server.WithDiscovery(false), server.WithSerial([6]byte{0, 0xFA, 1, 2, 3, 4}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := devmgmt.Dial(ctx, s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.Tunnel() == nil {
		t.Fatal("no tunnel")
	}
	if b, err := c.PropRead(ctx, devmgmt.ObjectDevice, 1, devmgmt.PIDSerialNumber, 1, 1); err != nil || string(b) != string([]byte{0, 0xFA, 1, 2, 3, 4}) {
		t.Fatalf("serial % X %v", b, err)
	}
	if b, err := c.PropRead(ctx, devmgmt.ObjectDevice, 1, devmgmt.PIDDeviceDescriptor, 1, 1); err != nil || b[0] != 0x09 || b[1] != 0x1A {
		t.Fatalf("device descriptor % X %v", b, err)
	}
	for name, read := range map[string]func() error{
		"instance 2": func() error {
			_, err := c.PropRead(ctx, devmgmt.ObjectDevice, 2, devmgmt.PIDSerialNumber, 1, 1)
			return err
		},
		"unknown object": func() error { _, err := c.PropRead(ctx, 0x0099, 1, devmgmt.PIDObjectType, 1, 1); return err },
		"index range": func() error {
			_, err := c.PropRead(ctx, devmgmt.ObjectDevice, 1, devmgmt.PIDSerialNumber, 2, 1)
			return err
		},
		"count 2 at 0": func() error {
			_, err := c.PropRead(ctx, devmgmt.ObjectDevice, 1, devmgmt.PIDSerialNumber, 0, 2)
			return err
		},
	} {
		err := read()
		var pe *devmgmt.PropertyError
		if !errors.As(err, &pe) || !errors.Is(err, knx.ErrRejected) || !strings.Contains(err.Error(), "devmgmt: object") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A function property command and a reset are answered (or ignored)
	// without breaking the connection.
	if err := c.Tunnel().Send(ctx, &cemi.FunctionProperty{MsgCode: cemi.MFuncPropCommandReq, ObjectType: 0, Instance: 1, PropertyID: 1}); err != nil {
		t.Fatal(err)
	}
	f, err := c.Tunnel().Receive(ctx)
	if fp, ok := f.(*cemi.FunctionProperty); err != nil || !ok || fp.MsgCode != cemi.MFuncPropCon {
		t.Fatalf("function property: %v %v", f, err)
	}
	if err := c.Tunnel().Send(ctx, &cemi.Reset{MsgCode: cemi.MResetReq}); err != nil {
		t.Fatal(err)
	}
	if n, err := c.PropElements(ctx, devmgmt.ObjectKNXnetIPParameter, 1, devmgmt.PIDAdditionalIndividualAddrs); err != nil || n != 1 {
		t.Fatalf("tunnelling addresses %d %v", n, err)
	}
	if err := (&devmgmt.PropertyError{Code: 0xEE}).Error(); !strings.Contains(err, "error (0xEE)") {
		t.Fatal(err)
	}
}
