// SPDX-License-Identifier: MIT

// Command virtual-server runs a KNXnet/IP server with a virtual device on
// the loopback interface, connects a tunnelling client to it, writes a
// switch and reads a temperature. It needs no KNX hardware.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/otfabric/go-knx"
	"github.com/otfabric/go-knx/client"
	"github.com/otfabric/go-knx/device"
	"github.com/otfabric/go-knx/server"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// A server with one virtual device: a switch (1/2/3) and a
	// temperature sensor (1/2/4) that answers reads.
	s, err := server.New(server.WithListenAddr("127.0.0.1:0"), server.WithDiscovery(false), server.WithName("example"))
	if err != nil {
		log.Fatal(err)
	}
	dev := device.New("living room", knx.MustParseIndividualAddress("1.1.1"))
	sw, _ := device.NewGroupObject("light", "1.001", "CRWU", "1/2/3")
	temp, _ := device.NewGroupObject("temperature", "9.001", "CRT", "1/2/4")
	_ = temp.Set(21.5)
	dev.Add(sw, temp)
	dev.OnChange(func(e device.Event) { fmt.Printf("device: %s %s = %v\n", e.Object.Name, e.Group, e.Value) })
	s.AddDevice(dev)
	if err := s.Start(ctx); err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	// A tunnelling client.
	c, err := client.DialTunnel(ctx, s.Addr().String(), nil)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	if err := c.GroupWrite(ctx, knx.MustParseGroupAddress("1/2/3"), true); err != nil {
		log.Fatal(err)
	}
	r, err := c.GroupRead(ctx, knx.MustParseGroupAddress("1/2/4"), client.WithDPT("9.001"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("read 1/2/4 from %s: %v °C\n", r.Source, r.Decoded)
}
